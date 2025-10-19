import numpy as np
import random
from typing import Tuple, List

class McElieceCryptosystem:
    def __init__(self, n: int = 64, k: int = 32, t: int = 5):
        self.n = n  # длина закодированного сообщения
        self.k = k  # длина исходного сообщения
        self.t = t  # количество ошибок для добавления
        
        self.G = None  
        self.S = None  
        self.P = None  
        self.G1 = None 
        self.H = None  
        
    def generate_generator_matrix(self):
        # гарантирует, что k бит соответствуют исходному слову
        k_eye = np.eye(self.k, dtype=int)
        
        # cлучайная бинарная матрица для избыточности (запутываем шифр) и объединяем
        A = np.random.randint(0, 2, size=(self.k, self.n - self.k))
        G = np.hstack([k_eye, A])
        
        # Создаем проверочную матрицу H = [A^T | nk_eye] для проверки кодовых слов 
        # на наличие ошибок и для их исправления
        # матрица G * H^T равны 0 (то есть матрица H напрямую исходит из матрицы G)
        nk_eye = np.eye(self.n - self.k, dtype=int)
        H = np.hstack([A.T, nk_eye])
        
        return G, H
    

    def generate_invertible_matrix(self, k: int):
        """
        Генерация случайной двоичной невырожденной (обратимой) матрицы S размера k x k
        Чтобы потом еще больше запутать матрицу G (первый шаг)
        """
        max_attempts = 100000
        for _ in range(max_attempts):
            # Случайная бинарная матрица
            S = np.random.randint(0, 2, size=(k, k))
            
            # Проверяем обратимость через вычисление обратной матрицы
            try:
                S_inv = self.matrix_inverse(S)
                # Проверяем, что S обратима потому что сообщение при расшифровке 
                # будет расшифровываться как раз при помощи обратной матрицы, 
                # отменяя эффект матрицы S
                product = np.dot(S, S_inv) % 2
                if np.array_equal(product, np.eye(k, dtype=int)):
                    return S
            except:
                continue
        
        return np.eye(k, dtype=int)
    

    def generate_permutation_matrix(self, size: int):
        """
        Генерация подстановочной матрицы P размера n x n
        тоже для перестановки элементов (столбцов) местами
        """
        P = np.eye(size, dtype=int)
        # случайная перестановка строк
        perm = np.random.permutation(size)
        P = P[perm]
        return P
    
    def matrix_inverse(self, matrix: np.ndarray):
        """
        Вычисление обратной матрицы
        """
        n = matrix.shape[0]
        augmented = np.hstack([matrix.copy(), np.eye(n, dtype=int)]).astype(int)
        
        for col in range(n):
            pivot_row = None
            for row in range(col, n):
                if augmented[row, col] == 1:
                    pivot_row = row
                    break
            
            if pivot_row is None:
                raise ValueError("Матрица вырожденная")
            
            # Меняем строки местами
            if pivot_row != col:
                augmented[[col, pivot_row]] = augmented[[pivot_row, col]]
            
            # Обнуляем все остальные элементы в столбце
            for row in range(n):
                if row != col and augmented[row, col] == 1:
                    augmented[row] = (augmented[row] + augmented[col]) % 2
        
        # Извлекаем обратную матрицу
        return augmented[:, n:].astype(int)
    
    def generate_keys(self):
        """
        Открытый ключ (G1, t) и секретный ключ (S, G, P)
        """
        # Шаг 1: Порождающая матрица G и проверочная матрица H
        self.G, self.H = self.generate_generator_matrix()
        
        # Шаг 2: Случайная двоичная невырожденная матрица S
        self.S = self.generate_invertible_matrix(self.k)
        
        # Шаг 3: Случайная подстановочной матрица P
        self.P = self.generate_permutation_matrix(self.n)
        
        # Шаг 4: Открытй ключ G1 = S * G * P
        temp = np.dot(self.S, self.G) % 2
        self.G1 = np.dot(temp, self.P) % 2
        
        return (self.G1, self.t)
    
    def generate_error_vector(self):
        """
        Генерация случайного вектора ошибок Z длины n (длина кодового слова) 
        (содержит ровно t единиц)
        """
        z = np.zeros(self.n, dtype=int)
        error_positions = random.sample(range(self.n), self.t)
        z[error_positions] = 1
        return z
    
    def text_to_binary(self, text: str):
        binary = []
        for char in text:
            byte_val = ord(char)
            bits = [int(b) for b in format(byte_val, '08b')]
            binary.extend(bits)
        return binary
    
    def binary_to_text(self, binary: List[int]):
        text = ""
        for i in range(0, len(binary), 8):
            byte_bits = binary[i:i+8]
            if len(byte_bits) == 8:
                byte_val = int(''.join(map(str, byte_bits)), 2)
                text += chr(byte_val)
        return text
    
    def encrypt_block(self, message_block: np.ndarray):
        """
        C = M * G1 + Z
        """
        z = self.generate_error_vector()
        
        c = (np.dot(message_block, self.G1) + z) % 2
        
        return c
    
    def encrypt(self, plaintext: str):
        print("Начало шифрования")
        
        binary = self.text_to_binary(plaintext)
        bin_len = len(binary)
        
        encrypted = []
        num_blocks = 0
        
        for i in range(0, len(binary), self.k):
            block = binary[i:i+self.k]
            
            # Дополняем последний блок нулями
            if len(block) < self.k:
                block.extend([0] * (self.k - len(block)))
            
            block_array = np.array(block, dtype=int)
            encrypted_block = self.encrypt_block(block_array)
            encrypted.extend(encrypted_block.tolist())
            num_blocks += 1
        
        return encrypted, bin_len
    
    def syndrome_decode(self, received: np.ndarray):
        """
        ДЕКОДИРОВАНИЕ С ИСПРАВЛЕНИЕМ ОШИБОК
        """
        # Вычисляем месторасположение ошибок
        syndrome = np.dot(received, self.H.T) % 2
        
        # Если синдром нулевой - ошибок нет
        if np.all(syndrome == 0):
            return received[:self.k]
        
        # Пытаемся исправить ошибки методом перебора для малых t
        if self.t <= 10:
            from itertools import combinations
            
            # Перебираем все комбинации позиций ошибок
            for num_errors in range(1, min(self.t + 1, 11)):
                for error_positions in combinations(range(self.n), num_errors):
                    # Создаем гипотетический вектор ошибок
                    error_vector = np.zeros(self.n, dtype=int)
                    error_vector[list(error_positions)] = 1
                    
                    # Пробуем исправить
                    corrected = (received + error_vector) % 2
                    test_syndrome = np.dot(corrected, self.H.T) % 2
                    
                    if np.all(test_syndrome == 0):
                        return corrected[:self.k]
        
        # Если не получилось исправить, возвращаем первые k бит
        return received[:self.k]
    
    def decrypt_block(self, cipher_block: np.ndarray):
        """
        1. C1 = C * P^(-1)
        2. Декодирование C1 с использованием алгоритма для G -> получаем M1
        3. M = M1 * S^(-1)
        """
        # Шаг 1: Ставим на место столбцы нашей матрицы P^(-1)
        P_inv = self.matrix_inverse(self.P)
        c1 = np.dot(cipher_block, P_inv) % 2
        
        # Шаг 2: Декодируем C1
        # C1 = M1 * G + e, где e - вектор ошибок
        # Используем алгоритм декодирования
        m1 = self.syndrome_decode(c1)
        
        # Шаг 3: Вычисляем M = M1 * S^(-1)
        S_inv = self.matrix_inverse(self.S)
        m = np.dot(m1, S_inv) % 2
        
        return m
    
    def decrypt(self, ciphertext: List[int], original_length: int):
        print(f"Начало расшифровывания")
        
        decrypted = []
        num_blocks = 0
        
        for i in range(0, len(ciphertext), self.n):
            block = ciphertext[i:i+self.n]
            
            if len(block) == self.n:
                block_array = np.array(block, dtype=int)
                decrypted_block = self.decrypt_block(block_array)
                decrypted.extend(decrypted_block.tolist())
                num_blocks += 1
        
        # Обрезаем до исходной длины
        decrypted = decrypted[:original_length]
        plaintext = self.binary_to_text(decrypted)
        
        return plaintext


def encrypt_file(input_file: str, output_file: str, mceliece: McElieceCryptosystem):
    with open(input_file, 'r', encoding='utf-8') as f:
        plaintext = f.read()
    
    ciphertext, original_bit_length = mceliece.encrypt(plaintext)
    
    with open(output_file, 'w') as f:
        f.write(f"{original_bit_length}\n")
        f.write(''.join(map(str, ciphertext)))


def decrypt_file(input_file: str, output_file: str, mceliece: McElieceCryptosystem):
    with open(input_file, 'r') as f:
        lines = f.readlines()
        original_length = int(lines[0].strip())
        ciphertext = [int(bit) for bit in lines[1].strip()]
    
    plaintext = mceliece.decrypt(ciphertext, original_length)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(plaintext)



if __name__ == "__main__":
    import time
    # n > k, потому что k - длина исходного сообщения, n = k + дополнение 
    mceliece = McElieceCryptosystem(n=64, k=32, t=3)
    public_key, t = mceliece.generate_keys()
    
    start = time.time()
    encrypt_file('plaintext.txt', 'encrypted.txt', mceliece)
    end_enc = time.time()
    decrypt_file('encrypted.txt', 'decrypted.txt', mceliece)
    end_dec = time.time()
    
    with open('plaintext.txt', 'r', encoding='utf-8') as f:
        original = f.read()
    
    with open('decrypted.txt', 'r', encoding='utf-8') as f:
        decrypted = f.read()
    
    if original == decrypted:
        print("УСПЕХ")
    else:
        print("Ошибка")
    
    print(f"\nИсходный текст:\n{original}")
    print(f"\nРасшифрованный текст:\n{decrypted}")

    print(f"\nВремя на шифрование: {end_enc-start}")
    print(f"\nВремя на расшифрование: {end_dec-end_enc}")
import random
import hashlib
from sympy import isprime


def generate_keys(bit_length=512):
    """ p and q are ≡ k mod 4 = 3. """
    p = 0
    q = 0

    # k*4 + 3
    while (p % 4) != 3 or not isprime(p):
        p = random.getrandbits(bit_length)
    while (q % 4) != 3 or not isprime(q) or q == p:
        q = random.getrandbits(bit_length)
    n = p * q
    return n, (p, q)

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    d, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return d, x, y

def decrypt_roots(c, p, q):
    n = p * q

    # алгоритм Евклида
    mp = pow(c, (p + 1) // 4, p)
    mq = pow(c, (q + 1) // 4, q)
    _, yp, yq = extended_gcd(p, q)

    # Chinese theorema
    r1 = (mq * yp * p + mp * yq * q) % n
    r2 = n - r1
    r3 = (mq * yp * p - mp * yq * q) % n
    r4 = n - r3
    return [r1, r2, r3, r4]


MARKER = b'\xFF'            # 1 byte marker
HASH_LEN = 32               # SHA-256 length
PAD_OVERHEAD = 1 + HASH_LEN # marker + hash

def pad_chunk_exact(data: bytes, payload_len: int) -> bytes:
    """
    Формирует блок фиксированной длины payload_len.
    Структура: [данные][нули для заполнения][МАРКЕР][SHA256(данных)].
    Гарантирует, что результат ровно payload_len байт.
    """
    if len(data) + PAD_OVERHEAD > payload_len:
        raise ValueError("data too large for payload length")
    h = hashlib.sha256(data).digest()
    # space left for zeros (between data and marker)
    zeros_len = payload_len - (len(data) + PAD_OVERHEAD)
    if zeros_len < 0:
        raise ValueError("payload_len too small")
    payload = data + (b'\x00' * zeros_len) + MARKER + h
    assert len(payload) == payload_len
    return payload

def unpad_and_verify(payload: bytes) -> bytes | None:
    """
    Проверяет корректность блока.
    Ожидается: [данные][нули][МАРКЕР][SHA256(данных)].
    Если хэш совпадает — возвращает данные, иначе None.
    """
    if len(payload) < PAD_OVERHEAD + 1:
        return None
    if payload[-(1 + HASH_LEN)] != MARKER[0]:
        return None
    data_and_zeros = payload[:-(1 + HASH_LEN)]
    data = data_and_zeros.rstrip(b'\x00')
    expected = payload[-HASH_LEN:]
    if hashlib.sha256(data).digest() == expected:
        return data
    return None


def encrypt_file(input_filename, output_filename, n):
    """
    Шифрует файл по схеме Рабина.
    Делит файл на блоки, добавляет паддинг, возводит каждый блок в квадрат mod n.
    Результаты записывает в output_filename.
    """
    # extend bytes len so it will not loose any byte
    full_len = (n.bit_length() + 7) // 8

    # payload_len: reserve 1 byte margin
    payload_len = full_len - 1
    max_data_len = payload_len - PAD_OVERHEAD

    with open(input_filename, 'rb') as f_in, open(output_filename, 'w') as f_out:
        while True:
            chunk = f_in.read(max_data_len)
            if not chunk:
                break
            padded = pad_chunk_exact(chunk, payload_len)  # exact length
            # convert to integer preserving the exact payload_len bytes
            m_int = int.from_bytes(padded, 'big')
            # m powered by 2 mod n
            c = pow(m_int, 2, n)
            f_out.write(str(c) + '\n')
    print(f"File '{input_filename}' encrypted in '{output_filename}'.")

def decrypt_file(input_filename, output_filename, p, q):
    """
    Дешифрует файл, зашифрованный по схеме Рабина.
    Для каждого шифртекста вычисляет 4 возможных корня и проверяет хэш,
    чтобы найти правильный.
    """
    n = p * q
    full_len = (n.bit_length() + 7) // 8
    payload_len = full_len - 1

    if payload_len <= 0:
        raise ValueError("Modulus too small for any payload bytes")

    with open(input_filename, 'r') as f_in, open(output_filename, 'wb') as f_out:
        for line in f_in:
            if not line.strip():
                continue
            c = int(line.strip())
            roots = decrypt_roots(c, p, q)
            correct_chunk = None

            for r in roots:
                # translate r to fixed full_len bytes (no overflow here because r < n)
                full_bytes = r.to_bytes(full_len, 'big')
                # take the last payload_len bytes (this exactly recovers the original payload bytes)
                payload_candidate = full_bytes[-payload_len:]
                data = unpad_and_verify(payload_candidate)
                if data is not None:
                    correct_chunk = data
                    break

            if correct_chunk is not None:
                f_out.write(correct_chunk)
            else:
                f_out.write(b'[DECRYPTION_ERROR]')
                print(f"[WARN] no valid root found for ciphertext: {c}")

    print(f"File '{input_filename}' is decrypted in '{output_filename}'.")


if __name__ == '__main__':
    public_key, private_key = generate_keys(512)
    n = public_key
    p, q = private_key

    with open("public_key.txt", "w") as f:
        f.write(str(n))
    with open("private_key.txt", "w") as f:
        f.write(f"{p}\n{q}")

    encrypt_file("test.txt", "encrypted.txt", n)
    decrypt_file("encrypted.txt", "decrypted.txt", p, q)

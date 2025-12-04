import jpeglib

BITS_FOR_LENGTH = 32
COEF_POS = (7, 7)

def string_to_bytes(s: str):
    return s.encode('utf-8')

def bytes_to_string(b: bytes):
    return b.decode('utf-8')

def hide_string_in_jpeg(string: str, source_image_path: str, hidden_image_path: str):
    with jpeglib.read_dct(source_image_path) as dct:
        y_coefficients = dct.Y  
        
        height_blocks, width_blocks, _, _ = y_coefficients.shape
        total_blocks = height_blocks * width_blocks
        
        bytes_string = string_to_bytes(string)
        string_length = len(bytes_string)
        bits_needed = BITS_FOR_LENGTH + string_length * 8
        
        if bits_needed > total_blocks:
            raise Exception(f"Изображение слишком маленькое. Нужно {bits_needed} блоков, доступно {total_blocks}")
        
        for bit_index in range(BITS_FOR_LENGTH):
            block_y = bit_index // width_blocks
            block_x = bit_index % width_blocks
            
            if block_y >= height_blocks or block_x >= width_blocks:
                break
            
            bit = (string_length >> (BITS_FOR_LENGTH - 1 - bit_index)) & 1
            coef_value = y_coefficients[block_y, block_x, COEF_POS[0], COEF_POS[1]]
            new_value = (coef_value & 0b11111110) | bit
            y_coefficients[block_y, block_x, COEF_POS[0], COEF_POS[1]] = new_value
        
        for bit_idx in range(string_length * 8):
            data_bit_index = BITS_FOR_LENGTH + bit_idx
            block_y = data_bit_index // width_blocks
            block_x = data_bit_index % width_blocks
            
            if block_y >= height_blocks or block_x >= width_blocks:
                break
            
            byte_idx = bit_idx // 8
            bit_pos = bit_idx % 8
            bit = (bytes_string[byte_idx] >> (7 - bit_pos)) & 1
            
            coef_value = y_coefficients[block_y, block_x, COEF_POS[0], COEF_POS[1]]
            new_value = (coef_value & 0b11111110) | bit
            y_coefficients[block_y, block_x, COEF_POS[0], COEF_POS[1]] = new_value
        
        dct.Y = y_coefficients
        dct.write_dct(hidden_image_path)


def extract_string_from_jpeg(hidden_image_path: str):
    with jpeglib.read_dct(hidden_image_path) as dct:
        y_coefficients = dct.Y 
        height_blocks, width_blocks, _, _ = y_coefficients.shape
        total_blocks = height_blocks * width_blocks
        
        string_length = 0
        for bit_index in range(BITS_FOR_LENGTH):
            block_y = bit_index // width_blocks
            block_x = bit_index % width_blocks
            
            if block_y >= height_blocks or block_x >= width_blocks:
                break
            
            coef_value = y_coefficients[block_y, block_x, COEF_POS[0], COEF_POS[1]]
            bit = coef_value & 1
            string_length = (string_length << 1) | bit
        
        if string_length <= 0:
            raise Exception(f"Неверная длина данных: {string_length}.")
        
        bytes_string = bytearray()
        for bit_idx in range(string_length * 8):
            data_bit_index = BITS_FOR_LENGTH + bit_idx
            
            block_y = data_bit_index // width_blocks
            block_x = data_bit_index % width_blocks
            
            if block_y >= height_blocks or block_x >= width_blocks:
                break
            
            coef_value = y_coefficients[block_y, block_x, COEF_POS[0], COEF_POS[1]]
            bit = coef_value & 1
            
            byte_idx = bit_idx // 8
            bit_pos = bit_idx % 8
            
            if bit_pos == 0:
                bytes_string.append(0)
            
            bytes_string[byte_idx] = (bytes_string[byte_idx] << 1) | bit
        
        return bytes_to_string(bytes(bytes_string))


if __name__ == "__main__":
    message = "Hello, world!"
    
    hide_string_in_jpeg(message, "lab8/cat.jpg", "lab8/hidden_cat.jpg")
    extracted = extract_string_from_jpeg("lab8/hidden_cat.jpg")
    
    print(f"Исходное сообщение: {message}")
    print(f"Извлеченное сообщение: {extracted}")
    print(f"Совпадение: {message == extracted}")

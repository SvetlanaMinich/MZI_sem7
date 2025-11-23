from PIL import Image
import numpy as np

def string_to_bytes(s: str):
    return s.encode('utf-8')

def bytes_to_string(b: bytes):
    return b.decode('utf-8')

def hide_string_in_image(string: str, source_image_path: str, hidden_image_path: str):
    img = Image.open(source_image_path)
    img_array = np.array(img)
    
    bytes_string = string_to_bytes(string)
    string_length = len(bytes_string)
    
    if len(img_array.shape) == 2:
        height, width = img_array.shape
        channels = 1
        flat_array = img_array.flatten()
    elif len(img_array.shape) == 3:
        height, width, channels = img_array.shape
        flat_array = img_array.flatten()
    else:
        raise Exception("Неподдерживаемый формат изображения")
    
    bits_needed = 32 + string_length * 8
    total_values = len(flat_array)
    
    if bits_needed > total_values:
        raise Exception(f"Изображение слишком маленькое")
    
    for i in range(32):
        bit = (string_length >> (31 - i)) & 1
        flat_array[i] = (flat_array[i] & 0b11111110) | bit
    
    for i in range(string_length * 8):
        value_index = 32 + i
        byte_index = i // 8
        bit_position = 7 - (i % 8)
        bit = (bytes_string[byte_index] >> bit_position) & 1
        flat_array[value_index] = (flat_array[value_index] & 0b11111110) | bit
    
    if len(img_array.shape) == 2:
        new_img_array = flat_array.reshape((height, width))
    else:
        new_img_array = flat_array.reshape((height, width, channels))
    
    new_img = Image.fromarray(new_img_array.astype(img_array.dtype))
    new_img.save(hidden_image_path)


def extract_string_from_image(hidden_image_path: str):
    img = Image.open(hidden_image_path)
    img_array = np.array(img)
    flat_array = img_array.flatten()
    
    string_length = 0
    for i in range(32):
        bit = flat_array[i] & 1 
        string_length = (string_length << 1) | bit
    
    bytes_string = bytearray()
    for i in range(string_length * 8):
        value_index = 32 + i
        bit = flat_array[value_index] & 1
        
        byte_index = i // 8
        bit_position = 7 - (i % 8)
        
        if i % 8 == 0:
            bytes_string.append(0)
        
        bytes_string[byte_index] |= (bit << bit_position)
    
    return bytes_to_string(bytes(bytes_string))

if __name__ == "__main__":
    hide_string_in_image("Hello, world!", "lab8/source.png", "lab8/hidden.png")
    print(extract_string_from_image("lab8/hidden.png"))
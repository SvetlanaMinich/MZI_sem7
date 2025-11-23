UINT32_MAX = 0xFFFFFFFF # 2^32 - 1

# S block = 4 bit
S_BLOCKS = [
    [4, 10, 9, 2, 13, 8, 0, 14, 6, 11, 1, 12, 7, 15, 5, 3],
    [14, 11, 4, 12, 6, 13, 15, 10, 2, 3, 8, 1, 0, 7, 5, 9],
    [5, 8, 1, 13, 10, 3, 4, 2, 14, 15, 12, 7, 6, 0, 9, 11],
    [7, 13, 10, 1, 0, 8, 9, 15, 14, 4, 6, 12, 11, 2, 5, 3],
    [6, 12, 7, 1, 5, 15, 13, 8, 4, 10, 9, 14, 0, 3, 11, 2],
    [4, 11, 10, 0, 7, 2, 1, 13, 3, 6, 8, 5, 9, 12, 15, 14],
    [13, 11, 4, 1, 3, 15, 5, 9, 0, 10, 14, 7, 6, 8, 2, 12],
    [1, 15, 13, 0, 5, 7, 10, 4, 9, 2, 3, 14, 6, 11, 8, 12]
]


def read_file_bytes(filepath):
    with open(filepath, 'rb') as f:
        return f.read()

def write_file_bytes(filepath, data):
    with open(filepath, 'wb') as f:
        f.write(data)


def add_mod_2_32(block, subkey):
    return (block + subkey) & UINT32_MAX

def s_block_substitution(value):
    result = 0
    # every 4 bits in half-block swap with S_BLOCKS number
    for i in range(8):
        block = (value >> (i * 4)) & 0xF  # 0xF - 0b1111
        substituted_block = S_BLOCKS[i][block]
        result |= (substituted_block << (i * 4))
    return result


def cycle_rotate_left(value):
    return ((value << 11) & UINT32_MAX) | (value >> (32 - 11)) 


def generate_subkeys(key_256_bit):
    subkeys = []
    # divide into 32-bit
    for i in range(8):
        subkey = (key_256_bit >> (256 - (i + 1) * 32)) & UINT32_MAX
        subkeys.append(subkey)
    
    encryption_subkeys = []
    for _ in range(3):
        encryption_subkeys.extend(subkeys)
    encryption_subkeys.extend(list(reversed(subkeys)))

    decryption_subkeys = list(reversed(encryption_subkeys))
    
    return encryption_subkeys, decryption_subkeys


def gost_block_crypt(block_64_bit, subkeys):
    A = (block_64_bit >> 32) & UINT32_MAX  # left
    B = block_64_bit & UINT32_MAX          # right

    for i in range(32):
        f = add_mod_2_32(B, subkeys[i])
        f = s_block_substitution(f)
        f = cycle_rotate_left(f)
        new_A = f ^ A    # sum mod 2 == XOR

        A = B
        B = new_A

    final_A = B
    final_B = A

    return (final_A << 32) | final_B


def bytes_to_int(bytes_data):
    return int.from_bytes(bytes_data, 'big')

def int_to_bytes(int_data, length):
    return int_data.to_bytes(length, 'big')

def padding(data, block_size=8):
    padding_len = block_size - (len(data) % block_size)
    padding = bytes([0]) * padding_len
    return data + padding, padding_len

def unpadding(data, padding_len):
    return data[:-padding_len]

def gost_simple_substitution(data, subkeys, padding_len=None, encrypt=True):
    block_size = 8 #bytes

    if encrypt:
        data, padding_len = padding(data, block_size)

    # divide data into 64-bit blocks
    processed_blocks = []
    for i in range(0, len(data), block_size):
        block_bytes = data[i:i + block_size]
        block_int = bytes_to_int(block_bytes)
        
        processed_block_int = gost_block_crypt(block_int, subkeys)
        processed_block_bytes = int_to_bytes(processed_block_int, block_size)
        processed_blocks.append(processed_block_bytes)

    result = b''.join(processed_blocks)

    if not encrypt:
        result = unpadding(result, padding_len)

    return result, padding_len if encrypt else None

if __name__ == '__main__':
    key = 0b0001000100100010001100110100010001010101011001100111011110001000100110011010101010111011110011001101110111101110111111110000000000010001001000100011001101000100010101010110011001110111100010001001100110101010101110111100110011011101111011101111111100000000
    
    with open('lab1/test.txt', 'r', encoding="utf-8") as f:
        original_text = f.read()
    original_bytes = original_text.encode('utf-8')

    print(f"Original text: {original_text}")
    
    encryption_subkeys, decryption_subkeys  = generate_subkeys(key)

    encrypted, padding_len = gost_simple_substitution(original_bytes, encryption_subkeys, encrypt=True)
    write_file_bytes('lab1/test-2.txt', encrypted)
    encrypted = read_file_bytes('lab1/test-2.txt')
    decrypted, _ = gost_simple_substitution(encrypted, decryption_subkeys, padding_len, encrypt=False)
    print(f"Decrypted text: {decrypted.decode('utf-8')}")
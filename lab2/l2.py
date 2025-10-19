import struct

H_TABLE = (
    (0xB1, 0x94, 0xBA, 0xC8, 0x0A, 0x08, 0x0B, 0xF5, 0x36, 0x6D, 0x00, 0xBE, 0x58, 0x4A, 0xA0, 0xE4),
    (0x85, 0x04, 0xFA, 0x90, 0x1B, 0xB6, 0xC7, 0xAC, 0x25, 0x2E, 0x72, 0xC2, 0x02, 0xFD, 0xCE, 0x0D),
    (0x5B, 0xB3, 0xD6, 0x12, 0x17, 0xB9, 0x61, 0x81, 0xFE, 0x67, 0xB0, 0xAD, 0x71, 0x6B, 0x89, 0x0E),
    (0x5C, 0xB0, 0xC0, 0xFF, 0x33, 0xC3, 0x56, 0x8B, 0x35, 0xC4, 0x05, 0xAE, 0xD8, 0xE0, 0x7F, 0x99),
    (0xE1, 0x2B, 0xDC, 0x1A, 0xE2, 0x82, 0x57, 0xEC, 0x70, 0x3F, 0xCC, 0xF0, 0x95, 0xEE, 0x8D, 0xF1),
    (0xC1, 0xAB, 0x78, 0x98, 0x9E, 0xE5, 0x7B, 0xCA, 0xF7, 0xC6, 0xF8, 0x60, 0xD5, 0xBB, 0x9C, 0x4F),
    (0xF3, 0x3C, 0x65, 0x7B, 0x63, 0x7C, 0x30, 0x6A, 0xDD, 0x4E, 0xA7, 0x79, 0x9B, 0xB2, 0x3D, 0x31),
    (0x75, 0x3E, 0x9D, 0x85, 0x6E, 0x27, 0xD3, 0xBC, 0xCF, 0x59, 0x1E, 0x18, 0x1F, 0x4C, 0x5A, 0x87),
    (0xE9, 0xDE, 0xE7, 0x2C, 0x88, 0x0C, 0x0F, 0xA6, 0x20, 0xD8, 0x49, 0xF4, 0x6F, 0x73, 0x96, 0x47),
    (0x90, 0x07, 0x53, 0x16, 0xED, 0x24, 0x7A, 0x37, 0x39, 0xCB, 0xA3, 0x83, 0x03, 0xA9, 0x8B, 0xF6),
    (0xA2, 0x92, 0xBD, 0x9B, 0x1C, 0xE5, 0xD1, 0x41, 0x01, 0x54, 0x45, 0xFB, 0xC9, 0x5E, 0x4D, 0x0F),
    (0xB8, 0x68, 0x20, 0xAA, 0x22, 0x7D, 0x64, 0x2F, 0x26, 0x87, 0xF9, 0x34, 0x90, 0x40, 0x55, 0x11),
    (0xBE, 0x32, 0x97, 0x13, 0x43, 0xFC, 0x9A, 0x48, 0xA0, 0x2A, 0xB8, 0x5F, 0x19, 0x4B, 0x09, 0xA1),
    (0x7E, 0xCD, 0xA4, 0xD0, 0x15, 0x44, 0xAF, 0x8C, 0xA5, 0x84, 0x50, 0xBF, 0x66, 0xD2, 0x1B, 0xBA),
    (0xA2, 0xD7, 0x46, 0x52, 0x42, 0xAB, 0xDF, 0xB3, 0x69, 0x74, 0xC5, 0x51, 0xEB, 0x23, 0x29, 0x21),
    (0xD4, 0xEF, 0xD9, 0xB4, 0x3A, 0x62, 0x28, 0x75, 0x91, 0x14, 0x10, 0xEA, 0x77, 0x6C, 0xDA, 0x12)
)

# Cycle G-rotation
ROTATION_VALUES = (5, 13, 21, 21, 13, 5, 21, 13, 5, 5, 13, 21, 21, 13, 5, 21)


def _h_transform(block_word):
    """H-transformation. Swap every 8-bit in 32-bit word"""
    result = 0
    for i in range(4):
        # extract 8-bit
        byte = (block_word >> (24 - i * 8)) & 0xFF
        # x/y from H
        row = (byte >> 4) & 0x0F  #0x0F == 0b00001111
        col = byte & 0x0F
        transformed_byte = H_TABLE[row][col]
        result |= (transformed_byte << (24 - i * 8))
    return result


def _g_transform(block_word, r):
    """G-transformation. H-transformation + left cycle rotation"""
    result = _h_transform(block_word)
    return ((result << r) | (result >> (32 - r))) & 0xFFFFFFFF


def _stb_encrypt_block(block, key_theta):
    # Step 1: Unpack 128-bit to 32-bit nums (a, b, c, d)
    a, b, c, d = struct.unpack('>IIII', block)
    
    # Step 2: Create subkeys
    k = [0] * 16
    for i in range(8):
        k[i] = key_theta[i]
        k[i + 8] = key_theta[i]
        
    # Step 3: 8-round encryption
    for i in range(8):
        t = (b + k[2*i]) & 0xFFFFFFFF
        a_ = a ^ _g_transform(t, ROTATION_VALUES[i])
        
        t = (c + k[2*i + 1]) & 0xFFFFFFFF
        d_ = d ^ _g_transform(t, ROTATION_VALUES[i+8])
        
        # swapping
        a,b,c,d = b,d_,c,a_

    # Step 4: Pack encrypted a, b, c, d 
    return struct.pack('>IIII', a,b,c,d)


def _stb_decrypt_block(block, key_theta):
    a, b, c, d = struct.unpack('>IIII', block)
    
    k = [0] * 16
    for i in range(8):
        k[i] = key_theta[i]
        k[i + 8] = key_theta[i]
        
    # reverse order
    for i in range(7, -1, -1):
        t = (a + k[2*i]) & 0xFFFFFFFF
        d_ = d ^ _g_transform(t, ROTATION_VALUES[i])
        
        t = (c + k[2*i+1]) & 0xFFFFFFFF
        b_ = b ^ _g_transform(t, ROTATION_VALUES[i+8])
        
        a,b,c,d = d_, a, c, b_
    
    return struct.pack('>IIII', a,b,c,d)


def _pad(text):
    padding_length = 16 - (len(text) % 16)
    return text + bytes([padding_length]) * padding_length


def _unpad(data):
    padding_length = data[-1]
    return data[:-padding_length]


def _generate_key_theta(key):
    """Generating 8 32-bit subkeys"""
    return list(struct.unpack('>IIIIIIII', key))  # I == uInt


def encrypt_simple_substitution(filepath, key):
    key_theta = _generate_key_theta(key)
    encrypted_data = b''
    with open(filepath, 'rb') as f_in:
        plaintext = f_in.read()
        padded_plaintext = _pad(plaintext)
        for i in range(0, len(padded_plaintext), 16):
            block = padded_plaintext[i:i+16]
            encrypted_data += _stb_encrypt_block(block, key_theta)
    return encrypted_data


def decrypt_simple_substitution(filepath, key):
    key_theta = _generate_key_theta(key)
    decrypted_data = b''
    with open(filepath, 'rb') as f_in:
        ciphertext = f_in.read()
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            decrypted_data += _stb_decrypt_block(block, key_theta)
    return _unpad(decrypted_data)


def encrypt_gamma_feedback(filepath, key, iv):
    key_theta = _generate_key_theta(key)
    output_data = b''
    gamma = iv
    with open(filepath, 'rb') as f_in:
        plaintext = f_in.read()
        padded_plaintext = _pad(plaintext)
        for i in range(0, len(padded_plaintext), 16):
            block = padded_plaintext[i:i+16]
            gamma = _stb_encrypt_block(gamma, key_theta)
            encrypted_block = bytes([p ^ g for p, g in zip(block, gamma)])
            output_data += encrypted_block
    return output_data


def decrypt_gamma_feedback(filepath, key, iv):
    key_theta = _generate_key_theta(key)
    output_data = b''
    gamma = iv
    with open(filepath, 'rb') as f_in:
        ciphertext = f_in.read()
        for i in range(0, len(ciphertext), 16):
            block = ciphertext[i:i+16]
            gamma = _stb_encrypt_block(gamma, key_theta)
            decrypted_block = bytes([c ^ g for c, g in zip(block, gamma)])
            output_data += decrypted_block
    return _unpad(output_data)


if __name__ == "__main__":
    KEY_HEX = "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF"
    IV_HEX = "FEDCBA9876543210FEDCBA9876543210"
    
    with open("test.txt", "w", encoding='utf-8') as f:
        f.write("This is a test message.\nЭто тестовое сообщение.")

    key_bytes = bytes.fromhex(KEY_HEX)
    iv_bytes = bytes.fromhex(IV_HEX)
    
    print("Режим простой замены-------------------------")
    encrypted_ecb = encrypt_simple_substitution("test.txt", key_bytes)
    print("Зашифрованный текст:", encrypted_ecb.hex())
    
    with open("test.txt.enc_ecb", "wb") as f_out:
        f_out.write(encrypted_ecb)
        
    decrypted_ecb = decrypt_simple_substitution("test.txt.enc_ecb", key_bytes)
    print("Расшифрованный текст:", decrypted_ecb.decode('utf-8'))
    
    print("\nРежим гаммирования с обратной связью-------------------------")
    encrypted_ofb = encrypt_gamma_feedback("test.txt", key_bytes, iv_bytes)
    print("Зашифрованный текст (hex):", encrypted_ofb.hex())
    
    with open("test.txt.enc_ofb", "wb") as f_out:
        f_out.write(encrypted_ofb)
    
    decrypted_ofb = decrypt_gamma_feedback("test.txt.enc_ofb", key_bytes, iv_bytes)
    print("Расшифрованный текст:", decrypted_ofb.decode('utf-8'))
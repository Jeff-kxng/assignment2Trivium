import os
import secrets
from collections import deque

def trivium_encryption(plaintext, key):
    # Generate a random Initialization Vector (IV) of 80 bits
    initialization_vector = secrets.randbits(80)

    # Convert key and IV to binary strings
    bit_key = format(key, '0>80b')
    bit_iv = format(initialization_vector, '0>80b')

    # Initialize Trivium state registers A, B, and C
    state = deque([*bit_iv, *[0] * (93 - 80), *bit_key, *[0] * (177 - 84), *[0] * 111, *[1] * 3])

    # Run Trivium algorithm to initialize
    for _ in range(1152):
        gen_keystream(state)

    # Generate keystream and encrypt the plaintext
    keystream = []
    ciphertext = []

    for i in range(len(plaintext)):
        output_bit = gen_keystream(state)
        keystream.append(output_bit)
        ciphertext.append(output_bit ^ plaintext[i])

    # Prepend IV to the ciphertext
    ciphertext_with_iv = initialization_vector.to_bytes(10, byteorder='big') + bytes(ciphertext)

    return ciphertext_with_iv

def gen_keystream(state):
    t1 = int(state[65]) ^ int(state[92])
    t2 = int(state[161]) ^ int(state[176])
    t3 = int(state[242]) ^ int(state[287])

    output_bit = t1 ^ t2 ^ t3

    t1 = t1 ^ (int(state[90]) & int(state[91])) ^ int(state[170])
    t2 = t2 ^ (int(state[174]) & int(state[175])) ^ int(state[263])
    t3 = t3 ^ (int(state[285]) & int(state[286])) ^ int(state[68])

    state.rotate()

    state[0] = t3
    state[93] = t1
    state[177] = t2

    return output_bit

def encrypt_file_with_trivium(plain_file_path, key):
    with open(plain_file_path, "rb") as plain_file:
        plain_file_binary = plain_file.read()

    ciphertext = trivium_encryption(plain_file_binary, key)

    encrypted_file_path = os.path.splitext(plain_file_path)[0] + "_encrypted.txt"

    with open(encrypted_file_path, 'wb') as encrypted_file:
        encrypted_file.write(ciphertext)

    return encrypted_file_path

key = 0x5DC67A3F4C1B3A543C9A
plain_file_path = "./03streamcipher.pdf"
encrypted_file_path = encrypt_file_with_trivium(plain_file_path, key)
print("Encryption complete.\nEncrypted file:", encrypted_file_path)

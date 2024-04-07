# aes_comparison.py
import os
import ctypes
import random
import string
import base64

import aes.aes as aes

from aes.aes import AES

# Load the C library
rijndael = ctypes.CDLL('./rijndael.so')

# Define the AES key size
AES_KEY_SIZE = 16

# Define the block size
BLOCK_SIZE = 16

# Define ctypes types for function arguments and return values
rijndael.sub_bytes.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
rijndael.shift_rows.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
rijndael.mix_columns.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
rijndael.invert_sub_bytes.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
rijndael.invert_shift_rows.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
rijndael.invert_mix_columns.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]
rijndael.add_round_key.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
rijndael.expand_key.argtypes = [ctypes.POINTER(ctypes.c_ubyte)]

rijndael.aes_encrypt_block.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
rijndael.aes_encrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)

rijndael.aes_decrypt_block.argtypes = [ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
rijndael.aes_decrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)

# AES key generation function
def generate_aes_key():
     return os.urandom(AES_KEY_SIZE)

# Random plaintext generation function
def generate_plaintext():
    return os.urandom(AES_KEY_SIZE)

# AES encryption function
def aes_encrypt(plaintext, key):
    # Convert plaintext and key to ctypes pointers
    plaintext_ptr = ctypes.cast(plaintext, ctypes.POINTER(ctypes.c_ubyte))
    key_ptr = ctypes.cast(key, ctypes.POINTER(ctypes.c_ubyte))
    # Call the C function
    return rijndael.aes_encrypt_block(plaintext_ptr, key_ptr)

# AES decryption function
def aes_decrypt(ciphertext, key):
    # Convert ciphertext and key to ctypes pointers
    ciphertext_ptr = ctypes.cast(ciphertext, ctypes.POINTER(ctypes.c_ubyte))
    key_ptr = ctypes.cast(key, ctypes.POINTER(ctypes.c_ubyte))
    # Call the C function
    return rijndael.aes_decrypt_block(ciphertext_ptr, key_ptr)

if __name__ == "__main__":

    # Generate random plaintext and key
    plaintext = generate_plaintext()
    key = generate_aes_key()
    # print
    # print("plaintext: ", base64.b64encode(plaintext).decode('utf-8'))
    # print("key------: ",base64.b64encode(key).decode('utf-8'))
    # print("\n")
    print("plaintext: ", [int(byte) for byte in plaintext])
    print("key------: ",[int(byte) for byte in key])
    print("\n")
    
    print("*********************** Python code ***********************************")
    # Python: 
    p_aes = AES(key)

    py_s = (ctypes.c_ubyte * BLOCK_SIZE)(*plaintext)
    # 将 ctypes 数组转换为二维数组
    py_s_2d = [[py_s[j * 4 + i] for i in range(4)] for j in range(4)]
    
    py_k = (ctypes.c_ubyte * BLOCK_SIZE)(*key)
    print("py_k: ",py_k)
    # 将 ctypes 数组转换为二维数组
    py_k_2d = [[py_k[j * 4 + i] for i in range(4)] for j in range(4)]
    print("py_k_2d: ",py_k_2d)

    # 调用 sub_bytes 函数
    aes.sub_bytes(py_s_2d)
    # 将结果重新写入 ctypes 数组
    for i in range(4):
        for j in range(4):
            py_s[i * 4 + j] = py_s_2d[i][j]
    # 输出结果
    print("sub_bytes result: ", [int(py_s[i]) for i in range(BLOCK_SIZE)])

    # 调用 def shift_rows(s) 并输出结果
    aes.shift_rows(py_s_2d)
    # 将结果重新写入 ctypes 数组
    for i in range(4):
        for j in range(4):
            py_s[i * 4 + j] = py_s_2d[i][j]
    print("shift_rows result: ", [int(py_s[i]) for i in range(BLOCK_SIZE)])

    # 调用 def mix_columns(s) 并输出结果
    aes.mix_columns(py_s_2d)
    # 将结果重新写入 ctypes 数组
    for i in range(4):
        for j in range(4):
            py_s[i * 4 + j] = py_s_2d[i][j]
    print("mix_columns result: ", [int(py_s[i]) for i in range(BLOCK_SIZE)])

    # 调用 def add_round_key(s, k) 并输出结果
    aes.add_round_key(py_s_2d, py_k_2d)
    for i in range(4):
        for j in range(4):
            py_s[i * 4 + j] = py_s_2d[i][j]
    print("add_round_key result: ", [int(py_s[i]) for i in range(BLOCK_SIZE)])
    print("\n")

    # 调用 def _expand_key(self, master_key) 并输出结果
    p_expanded_key = p_aes._expand_key(key)
    print("p_expandedKey: ", p_expanded_key)

    print("\n")
    # Encrypt def decrypt_block(self, ciphertext)
    p_ciphertext = p_aes.encrypt_block(plaintext)
    # 十进制输出ciphertext
    print("p_ciphertext: ", [int(p_ciphertext[i]) for i in range(BLOCK_SIZE)])
    print("\n")

    py_ciphertext = (ctypes.c_ubyte * BLOCK_SIZE)(*p_ciphertext)
    # 将 ctypes 数组转换为二维数组
    py_ciphertext_2d = [[py_ciphertext[j * 4 + i] for i in range(4)] for j in range(4)]

    # 调用 def inv_sub_bytes(s) 并输出结果
    aes.inv_sub_bytes(py_ciphertext_2d)
    # 将结果重新写入 ctypes 数组
    for i in range(4):
        for j in range(4):
            py_ciphertext[i * 4 + j] = py_ciphertext_2d[i][j]
    print("inv_sub_bytes result: ", [int(py_ciphertext[i]) for i in range(BLOCK_SIZE)])

    # 调用 def inv_shift_rows(s) 并输出结果
    aes.inv_shift_rows(py_ciphertext_2d)
    # 将结果重新写入 ctypes 数组
    for i in range(4):
        for j in range(4):
            py_ciphertext[i * 4 + j] = py_ciphertext_2d[i][j]
    print("inv_shift_rows result: ", [int(py_ciphertext[i]) for i in range(BLOCK_SIZE)])

    # 调用 def inv_mix_columns(s) 并输出结果
    aes.inv_mix_columns(py_s_2d)
    # 将结果重新写入 ctypes 数组
    for i in range(4):
        for j in range(4):
            py_ciphertext[i * 4 + j] = py_ciphertext_2d[i][j]
    print("inv_mix_columns result: ", [int(py_ciphertext[i]) for i in range(BLOCK_SIZE)])

    print("\n")
    # Decrypt def encrypt_block(self, plaintext)
    p_decrypted_text = p_aes.decrypt_block(p_ciphertext)
    # 十进制输出decrypted_text
    print("p_decrypted_text: ", [int(p_decrypted_text[i]) for i in range(BLOCK_SIZE)])

    print("*********************** C code ***********************************")
    # C:
    c_s = (ctypes.c_ubyte * BLOCK_SIZE)(*plaintext)
    c_k = (ctypes.c_ubyte * BLOCK_SIZE)(*key)
    # 调用 void sub_bytes(unsigned char *block),将计算结果以十进制输出
    
    print("\n")
    rijndael.sub_bytes(c_s)
    print("sub_bytes result: ", [int(c_s[i]) for i in range(BLOCK_SIZE)])
    
    # 调用 void shift_rows(unsigned char *block),将计算结果以十进制输出
    # s = (ctypes.c_ubyte * BLOCK_SIZE)(*plaintext)
    rijndael.shift_rows(c_s)
    print("shift_rows result: ", [int(c_s[i]) for i in range(BLOCK_SIZE)])
    
    # 调用 void mix_columns(unsigned char *block),将计算结果以十进制输出
    # s = (ctypes.c_ubyte * BLOCK_SIZE)(*plaintext)
    rijndael.mix_columns(c_s)
    print("mix_columns result: ", [int(c_s[i]) for i in range(BLOCK_SIZE)])

    # 调用 void invert_sub_bytes(unsigned char *block),将计算结果以十进制输出
    # 调用 void invert_shift_rows(unsigned char *block),将计算结果以十进制输出
    # 调用 void invert_mix_columns(unsigned char *block),将计算结果以十进制输出

    # 调用 void add_round_key(unsigned char *block, unsigned char *round_key),将计算结果以十进制输出
    rijndael.add_round_key(c_s,c_k)
    print("add_round_key result: ", [int(c_s[i]) for i in range(BLOCK_SIZE)])
    print("\n")
    
    # 调用 unsigned char *expand_key(unsigned char *cipher_key),将计算结果以十进制输出
    # c_expand_key = rijndael.expand_key(c_k)
    # print("expand_key result: ", c_expand_key)
    # print("\n")

    # 调用 unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key),将计算结果以十进制输出
    # Encrypt with C implementation
    c_cipher = aes_encrypt(plaintext, key)
    # Convert c_cipher to a list of integers
    c_cipher_dec = [int(c_cipher[i]) for i in range(BLOCK_SIZE)]
    print("c_cipher: ", c_cipher_dec)
    
    print("\n")
    # 调用 unsigned char *aes_decrypt_block(unsigned char *ciphertext, unsigned char *key),将计算结果以十进制输出
    # Decrypt with C implementation
    c_decrypted_text = aes_decrypt(c_cipher, key)
    c_decrypted_text_dec = [int(c_decrypted_text[i]) for i in range(BLOCK_SIZE)]
    print("c_decrypted_text: ", c_decrypted_text_dec)

# Final unit test
def final_unit_test():
    for _ in range(3):
        # Generate random plaintext and key
        plaintext = generate_plaintext()
        key = generate_aes_key()
        aes = AES(key)

        p_expandedKey = aes._expand_key(key)
        # 此处需要将p_expandedKey转化为10进制数字输出
        print("p_expandedKey: ", p_expandedKey)

        print("plaintext: ", base64.b64encode(plaintext).decode('utf-8'))
        print("key------: ",base64.b64encode(key).decode('utf-8'))
        print("\n")
        print("plaintext: ", [int(byte) for byte in plaintext])
        print("key------: ",[int(byte) for byte in key])
        print("\n")

        # Encrypt with C implementation
        c_cipher = aes_encrypt(plaintext, key)
        # Convert c_cipher to a list of integers
        c_cipher_dec = [int(c_cipher[i]) for i in range(BLOCK_SIZE)]
        print("c_cipher: ", c_cipher_dec)

        # Encrypt with Python implementation
        p_cipher = aes.encrypt_block(plaintext)
        print("p_cipher: ", [int(byte) for byte in p_cipher])

        print("\n")

        # Decrypt with C implementation
        c_decrypted_text = aes_decrypt(c_cipher, key)
        c_decrypted_text_dec = [int(c_decrypted_text[i]) for i in range(BLOCK_SIZE)]
        print("c_decrypted_text: ", c_decrypted_text_dec)

        # Decrypt with Python implementation
        p_decrypted_text = aes.decrypt_block(p_cipher)
        print("p_decrypted_text: ", [int(byte) for byte in p_decrypted_text])

# Run the final unit test
# final_unit_test()
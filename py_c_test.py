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
rijndael.expand_key.restype = ctypes.POINTER(ctypes.c_ubyte)

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

# C: AES encryption function
def aes_encrypt(plaintext, key):
    # Convert plaintext and key to ctypes pointers
    plaintext_ptr = ctypes.cast(plaintext, ctypes.POINTER(ctypes.c_ubyte))
    key_ptr = ctypes.cast(key, ctypes.POINTER(ctypes.c_ubyte))
    # Call the C function
    return rijndael.aes_encrypt_block(plaintext_ptr, key_ptr)

# C: AES decryption function
def aes_decrypt(ciphertext, key):
    # Convert ciphertext and key to ctypes pointers
    ciphertext_ptr = ctypes.cast(ciphertext, ctypes.POINTER(ctypes.c_ubyte))
    key_ptr = ctypes.cast(key, ctypes.POINTER(ctypes.c_ubyte))
    # Call the C function
    return rijndael.aes_decrypt_block(ciphertext_ptr, key_ptr)

# Define a helper function to copy memory
def memcpy(dst, src, count):
    ctypes.memmove(dst, src, count)

# convert the result to a list of integers
def ptr_to_list(ptr, size):
    return [int(ptr[i]) for i in range(size)]

# Converts a 16-byte array into a 4x4 matrix.
def bytes2matrix(text):
    return [list(text[i:i+4]) for i in range(0, len(text), 4)]

# Converts a 4x4 matrix into 1D array.
def flattenMatrix(matrix):
    return [item for sublist in matrix for item in sublist]

def printMatrix(text):
    return [char for char in text]

# if __name__ == "__main__":
def final_unit_test():
    for i in range(3):
        print("*********************** Plaintext-key for Unit Test: %d ***********************************"%(i+1))
        # Generate random plaintext and key
        plaintext = generate_plaintext()
        key = generate_aes_key()
        # print plaint and key with matrix
        print("plaintext: ", flattenMatrix(bytes2matrix(plaintext)))
        print("key------: ", flattenMatrix(bytes2matrix(key)))

        print("*********************** Python code *************************************")
        # instantiate a AES object for encrypt/decrypt process
        p_aes = AES(key)

        # transform plaintext to 4x4 matrix
        py_s_2d = bytes2matrix(plaintext)
        
        # transform py_k to 4x4 matrix
        py_k_2d = bytes2matrix(key)

        # call sub_bytes
        aes.sub_bytes(py_s_2d)
        p_sub_bytes = flattenMatrix(py_s_2d)
        print("p_sub_bytes: ",p_sub_bytes)

        # call def shift_rows(s) 
        aes.shift_rows(py_s_2d)
        p_shift_rows = flattenMatrix(py_s_2d)
        print("p_shift_rows: ",p_shift_rows)

        # call def mix_columns(s)
        aes.mix_columns(py_s_2d)
        p_mix_columns = flattenMatrix(py_s_2d)
        print("p_mix_columns: ",p_mix_columns)

        # call def add_round_key(s, k) 
        aes.add_round_key(py_s_2d, py_k_2d)
        p_add_round_key = flattenMatrix(py_s_2d)
        print("p_add_round_key: ", p_add_round_key)

        # call def _expand_key(self, master_key) 
        p_expanded_key = p_aes._expand_key(key)
        # Convert byte strings to decimal arrays
        p_expanded_key_list = [int(byte) for matrix in p_expanded_key for item in matrix for byte in item]
        print("p_expandedKey: ", p_expanded_key_list)

        # Encrypt def encrypt_block(self, ciphertext)
        p_ciphertext = p_aes.encrypt_block(plaintext)
        # convert to matrix
        p_cipher_2d = bytes2matrix(p_ciphertext)
        
        # conver matrix to 1D array and print to console
        p_cipherArray = flattenMatrix(p_cipher_2d)
        print("p_ciphertext: ",p_cipherArray)

        # copy for invert process
        p_cipher2d_copy = p_cipher_2d

        # call def inv_sub_bytes(s) 
        aes.inv_sub_bytes(p_cipher2d_copy)
        p_inv_sub_bytes = flattenMatrix(p_cipher2d_copy)
        print("p_inv_sub_bytes: ",p_inv_sub_bytes)

        # call def inv_shift_rows(s) 
        aes.inv_shift_rows(p_cipher2d_copy)
        p_inv_shift_rows = flattenMatrix(p_cipher2d_copy)
        print("p_inv_shift_rows: ",p_inv_shift_rows)

        # call def inv_mix_columns(s)
        aes.inv_mix_columns(p_cipher2d_copy)
        p_inv_mix_columns = flattenMatrix(p_cipher2d_copy)
        print("p_inv_mix_columns: ",p_inv_mix_columns)

        # Decrypt def encrypt_block(self, plaintext)
        p_decrypted_text = p_aes.decrypt_block(p_ciphertext)
        # conver matrix to 1D array and print to console
        p_decrypted_textArray = flattenMatrix(bytes2matrix(p_decrypted_text))
        print("p_decrypted_text: ",p_decrypted_textArray)

        print("*********************** C code ***********************************")
        # C:
        c_s = (ctypes.c_ubyte * BLOCK_SIZE)(*plaintext)
        c_k = (ctypes.c_ubyte * BLOCK_SIZE)(*key)

        # call void sub_bytes(unsigned char *block)
        rijndael.sub_bytes(c_s)
        c_sub_bytes = printMatrix(c_s)
        print("c_sub_bytes: ",c_sub_bytes)

        assert c_sub_bytes == p_sub_bytes
        
        # call void shift_rows(unsigned char *block)
        rijndael.shift_rows(c_s)
        c_shift_rows = printMatrix(c_s)
        print("c_shift_rows: ",c_shift_rows)

        assert c_shift_rows == p_shift_rows
        
        # call void mix_columns(unsigned char *block)
        rijndael.mix_columns(c_s)
        c_mix_columns = printMatrix(c_s)
        print("c_mix_columns: ",c_mix_columns)

        assert c_mix_columns == p_mix_columns

        # call void add_round_key(unsigned char *block, unsigned char *round_key)
        rijndael.add_round_key(c_s,c_k)
        c_add_round_key = printMatrix(c_s)
        print("c_add_round_key: ",c_add_round_key)

        assert c_add_round_key == p_add_round_key

        # call unsigned char *expand_key(unsigned char *cipher_key)
        c_expand_key_ptr = rijndael.expand_key(c_k)
        c_expand_key_list = ptr_to_list(c_expand_key_ptr, 176)
        print("c_expand_key_list: ",c_expand_key_list)

        assert c_expand_key_list == p_expanded_key_list

        # call unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key)
        # Encrypt with C implementation
        c_cipher_ptr = aes_encrypt(plaintext, key)
        # Convert c_cipher to a list of integers
        c_cipher_dec = ptr_to_list(c_cipher_ptr, 16)
        print("c_cipher: ", c_cipher_dec)

        assert c_cipher_dec == p_cipherArray

        # Create a copy for decrypt
        c_cipher_copy = (ctypes.c_ubyte * BLOCK_SIZE)()
        memcpy(c_cipher_copy, c_cipher_ptr, BLOCK_SIZE)

        # call void invert_sub_bytes(unsigned char *block)
        rijndael.invert_sub_bytes(c_cipher_ptr)
        c_invert_sub_bytes = ptr_to_list(c_cipher_ptr, 16)
        print("c_invert_sub_bytes: ", c_invert_sub_bytes)

        assert c_invert_sub_bytes == p_inv_sub_bytes

        # call void invert_shift_rows(unsigned char *block)
        rijndael.invert_shift_rows(c_cipher_ptr)
        c_invert_shift_rows = ptr_to_list(c_cipher_ptr, 16)
        print("c_invert_shift_rows: ",c_invert_shift_rows)

        assert c_invert_shift_rows == p_inv_shift_rows

        # call void invert_mix_columns(unsigned char *block)
        rijndael.invert_mix_columns(c_cipher_ptr)
        c_invert_mix_columns = ptr_to_list(c_cipher_ptr, 16)
        print("c_invert_mix_columns: ",c_invert_mix_columns)

        assert c_invert_mix_columns == p_inv_mix_columns

        # Decrypt with C implementation
        c_decrypted_text = aes_decrypt(c_cipher_copy, key)
        c_decrypted_text_array = ptr_to_list(c_decrypted_text, 16)
        print("c_decrypted_text: ", c_decrypted_text_array)

        assert c_decrypted_text_array == p_decrypted_textArray

# Run unit test
final_unit_test()
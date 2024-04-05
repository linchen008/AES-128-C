/*
 * TODO: Add your name and student number here, along with
 *       a brief description of this code.
 * Name: Lin Chen
 * Number: D23125391
 */

#ifndef RIJNDAEL_H
#define RIJNDAEL_H

#define BLOCK_ACCESS(block, row, col) (block[(row * 4) + col])
#define BLOCK_SIZE 16          // 16 bytes == 128 bits
#define NUM_ROUNDS 10          // Number of rounds for AES-128
#define EXPANDED_KEY_SIZE 176  // BLOCK_SIZE * (num_rounds+1)

/*
 * These should be the main encrypt/decrypt functions (i.e. the main
 * entry point to the library for programmes hoping to use it to
 * encrypt or decrypt data)
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key);
unsigned char *aes_decrypt_block(unsigned char *ciphertext, unsigned char *key);

#endif

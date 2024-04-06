#include <stdio.h>
#include <stdlib.h>

#include "rijndael.h"

void print_128bit_block(unsigned char *block) {
  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
      unsigned char value = BLOCK_ACCESS(block, i, j);

      // Print spaces before small numbers to ensure that everything is aligned
      // and looks nice
      if (value < 10) printf(" ");

      if (value < 100) printf(" ");

      printf("%d", value);
    }
    printf("\n");
  }
}

int main() {
  unsigned char plaintext[16] = {1, 2,  3,  4,  5,  6,  7,  8,
                                 9, 10, 11, 12, 13, 14, 15, 16};
  unsigned char key[16] = {50, 20, 46, 86, 67, 9, 70, 27,
                           75, 17, 51, 17, 4,  8, 6,  99};

  unsigned char *ciphertext = aes_encrypt_block(plaintext, key);
  unsigned char *recovered_plaintext = aes_decrypt_block(ciphertext, key);

  printf("############ ORIGINAL PLAINTEXT ###########\n");
  print_128bit_block(plaintext);

  printf("\n\n################ CIPHERTEXT ###############\n");
  print_128bit_block(ciphertext);

  printf("\n\n########### RECOVERED PLAINTEXT ###########\n");
  print_128bit_block(recovered_plaintext);

  // free(ciphertext);
  // free(recovered_plaintext);

  printf("\n\n##########################################################\n");

  printf("\nCipher Key (HEX format):\n");
  for (int i = 0; i < 16; i++) {
    // Print characters in HEX format, 16 chars per line
    printf("%2.2x%c", key[i], ((i + 1) % 16) ? ' ' : '\n');
  }

  // Test the Key Expansion
  unsigned char *expanded_key = expand_key(key);
  printf("\nExpanded Key (HEX format):\n");

  for (int i = 0; i < EXPANDED_KEY_SIZE; i++) {
    printf("%2.2x%c", expanded_key[i], ((i + 1) % 16) ? ' ' : '\n');
  }

  printf("\nPlaintext (HEX format):\n");
  for (int i = 0; i < 16; i++) {
    printf("%2.2x%c", plaintext[i], ((i + 1) % 16) ? ' ' : '\n');
  }
  printf("\n");

  // Encrypt the plaintext using AES
  // unsigned char *ciphertext = aes_encrypt_block(plaintext, key);

  // Print the encrypted ciphertext
  printf("Encrypted Ciphertext:\n");
  for (int i = 0; i < BLOCK_SIZE; i++) {
    printf("%2.2x%c", ciphertext[i], ((i + 1) % 16) ? ' ' : '\n');
  }
  printf("\n");

  // Decrypt the plaintext using AES
  // unsigned char *decryptedtext = aes_decrypt_block(ciphertext, key);
  printf("\nDecrypted text (HEX format):\n");

  for (int i = 0; i < 16; i++) {
    printf("%2.2x%c", recovered_plaintext[i], ((i + 1) % 16) ? ' ' : '\n');
  }
  printf("\n");

  // Free the memory allocated for decryptedtext
  free(recovered_plaintext);
  free(ciphertext);
  free(expanded_key);

  return 0;
}

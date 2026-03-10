#ifndef CRYPTO_H
#define CRYPTO_H


#include <stddef.h>

#define KEY_LEN 32 // AES-256
#define IV_LEN 12 
#define TAG_LEN 16

int encrypt_payload(
    const unsigned char *plaintext,
    size_t plaintext_len,
    const unsigned char *key,
    unsigned char **output,
    size_t *output_len
);

int decrypt_payload(
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    const unsigned char *key,
    unsigned char **output,
    size_t *output_len
);

#endif
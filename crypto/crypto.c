#include "crypto.h"
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>

void handleErrors(void){
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt_payload(
    const unsigned char *plaintext,
    size_t plaintext_len,
    const unsigned char *key,
    unsigned char **output,
    size_t *output_len
){
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *ciphertext = NULL;
    unsigned char iv[IV_LEN];
    unsigned char tag[TAG_LEN];
    int len;
    int ciphertext_len;

    *output = NULL;
    *output_len = 0;

    if(!RAND_bytes(iv, IV_LEN))
        return -1;

    ctx = EVP_CIPHER_CTX_new();
    if(!ctx)
        return -1;

    if(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto error;

    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1)
        goto error;

    if(EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        goto error;

    ciphertext = malloc(plaintext_len);
    if(!ciphertext)
        goto error;

    if(EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1)
        goto error;

    ciphertext_len = len;

    if(EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
        goto error;

    ciphertext_len += len;

    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1)
        goto error;

    *output_len = IV_LEN + ciphertext_len + TAG_LEN;  
    *output = malloc(*output_len);
    if(!*output)
        goto error;

    memcpy(*output, iv, IV_LEN);                                    // bytes 0-11: IV
    memcpy(*output + IV_LEN, ciphertext, ciphertext_len);           // bytes 12 to 12+N-1: ciphertext
    memcpy(*output + IV_LEN + ciphertext_len, tag, TAG_LEN);       // bytes 12+N to 12+N+15: tag

    free(ciphertext);
    EVP_CIPHER_CTX_free(ctx);

    /*
    printf("[C encrypt] Input plaintext length: %zu\n", plaintext_len);
    printf("[C encrypt] Output length: %zu (IV=%d + ciphertext=%d + tag=%d)\n", 
        *output_len, IV_LEN, ciphertext_len, TAG_LEN);
    printf("[C encrypt] Layout check: %zu == %d? %s\n",
        *output_len, IV_LEN + ciphertext_len + TAG_LEN,
        (*output_len == IV_LEN + ciphertext_len + TAG_LEN) ? "YES" : "NO");

    printf("[C encrypt] First 16 bytes of output: ");
    for (int i = 0; i < 16 && i < (int)*output_len; i++) {
        printf("%02x", (*output)[i]);
    }
    printf("\n");

    printf("[C encrypt] Last 16 bytes of output (should be tag): ");
    size_t start = *output_len >= 16 ? *output_len - 16 : 0;
    for (size_t i = start; i < *output_len; i++) {
        printf("%02x", (*output)[i]);
    }
    printf("\n");
    */
    return 0;

error:
    if(ciphertext)
        free(ciphertext);
    if(ctx)
        EVP_CIPHER_CTX_free(ctx);
    if(*output) {
        free(*output);
        *output = NULL;
    }
    return -1;
}

int decrypt_payload(
    const unsigned char *ciphertext,
    size_t ciphertext_len,
    const unsigned char *key,
    unsigned char **output,
    size_t *output_len
) {
    if (ciphertext_len < IV_LEN + TAG_LEN)
        return -1;

    const unsigned char *iv = ciphertext;                           // First 12 bytes
    const unsigned char *enc = ciphertext + IV_LEN;                 // Middle bytes
    size_t enc_len = ciphertext_len - IV_LEN - TAG_LEN;            // Ciphertext length
    const unsigned char *tag = ciphertext + IV_LEN + enc_len;      // Last 16 bytes

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -1;

    unsigned char *plaintext = malloc(enc_len > 0 ? enc_len : 1);
    if (!plaintext)
        goto error;

    int len;
    int plaintext_len;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto error;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, NULL) != 1)
        goto error;

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        goto error;

    if (EVP_DecryptUpdate(ctx, plaintext, &len, enc, enc_len) != 1)
        goto error;

    plaintext_len = len;

    // Set the tag BEFORE calling DecryptFinal
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (void *)tag) != 1)
        goto error;

    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1) {
        // AUTH FAILURE - tag didn't match
        goto error;
    }

    plaintext_len += len;

    *output = plaintext;
    *output_len = plaintext_len;
    EVP_CIPHER_CTX_free(ctx);
    return 0;

error:
    if (plaintext)
        free(plaintext);
    if (ctx)
        EVP_CIPHER_CTX_free(ctx);
    return -1;
}
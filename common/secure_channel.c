#include "secure_channel.h"
#include "framing.h"
#include "../crypto/crypto.h"
#include <stdlib.h>

int send_secure(int fd, uint8_t type, const unsigned char *payload, uint32_t payload_len, const unsigned char *key){
    unsigned char *enc = NULL;
    size_t enc_len = 0;

    if(encrypt_payload(payload, payload_len, key, &enc, &enc_len) < 0)
        return -1;

    // Convert to uint32_t safely for framing
    if (enc_len > UINT32_MAX) {
        free(enc);
        return -1;
    }    

    int ret = send_frame(fd, type, enc, enc_len);

    free(enc);
    return ret; 
}

int recv_secure(int fd, uint8_t *type, unsigned char **payload, uint32_t *payload_len, const unsigned char *key){
    unsigned char *enc = NULL;
    uint32_t enc_len = 0;

    if(recv_frame(fd, type, &enc, &enc_len) < 0)
        return -1;

    unsigned char *plain = NULL;
    size_t plain_len = 0;

    if(decrypt_payload(enc, enc_len ,key, &plain, &plain_len) < 0){
        free(enc);
        return -1;
    }

    free(enc);

    if (plain_len > UINT32_MAX) {
        free(plain);
        return -1;
    }
    *payload = plain;
    *payload_len = (uint32_t)plain_len;

    return 0;
}
#ifndef SECURE_CHANNEL_H
#define SECURE_CHANNEL_H

#include <stdint.h>
#include <stddef.h>

int send_secure(int fd, uint8_t type, const unsigned char *payload, uint32_t payload_len, const unsigned char *key);

int recv_secure(int fd, uint8_t *type, unsigned char **payload, uint32_t *payload_len, const unsigned char *key);

#endif
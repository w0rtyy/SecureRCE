
#ifndef FRAMING_H
#define FRAMING_H

#include <stdint.h>
#include <stddef.h>


// Secure (encrypted) framing functions
int send_frame(int fd, uint8_t type, const unsigned char *payload, uint32_t payload_length);

int recv_frame(int fd, uint8_t *type, unsigned char **payload, uint32_t *payload_length);


#endif
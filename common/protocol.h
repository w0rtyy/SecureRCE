#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <stdint.h>

#define MAX_PAYLOAD 4096
#define MAX_FRAME_SIZE 65536

typedef enum{
    MSG_HELLO = 1,          // Handshake pubkey(PT) or auth Payload(encrypted)
    MSG_AUTH_OK = 2,        // server confirms identity
    MSG_JOB_REQUEST = 3,    // CLI -> server : "run this command"
    MSG_JOB_ASSIGN = 4,     // server -> Agent : "execute this"
    MSG_JOB_OUTPUT = 5,     // Agent -> server -> CLI : stdout/stderr chunk 
    MSG_JOB_EXIT = 6,       // Agent -> server : job done, exit code
    MSG_ERROR = 7
} msg_type_t;

#endif

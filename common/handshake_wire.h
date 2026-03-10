#ifndef HANDSHAKE_WIRE_H
#define HANDSHAKE_WIRE_H

// Perform the server side of the handshake on an accepted fd.
// On success: writes 32-byte session key into session_key_out, returns 0.
// On failure: returns -1.
int server_handshake(int fd, unsigned char session_key_out[32]);


// Perform the agent/client side of the handshake on a connected fd.
// On success: writes 32-byte session key into session_key_out, returns 0.
// On failure: returns -1.
int agent_handshake(int fd, unsigned char session_key_out[32]);

#endif
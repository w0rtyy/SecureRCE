CC      = gcc
CFLAGS  = -Wall -Wextra -g -I.
LDFLAGS = -lssl -lcrypto

CRYPTO_SRC  = crypto/crypto.c crypto/handshake.c
COMMON_SRC  = common/framing.c common/secure_channel.c \
              common/handshake_wire.c common/auth.c

all: agent/agent-001 agent/agent-002 user/cli

agent/agent-001: agent/agent-001.c $(COMMON_SRC) $(CRYPTO_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

agent/agent-002: agent/agent-002.c $(COMMON_SRC) $(CRYPTO_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

user/cli: user/cli.c $(COMMON_SRC) $(CRYPTO_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f agent/agent-001 agent/agent-002 user/cli

.PHONY: all clean
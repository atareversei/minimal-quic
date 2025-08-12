# minimal-quic-c

A minimal QUIC protocol implementation in C, designed as a learning project  
to explore UDP sockets, packet encoding/decoding, and connection basics.

## Project Structure

- `src/` — source code for client, server, UDP helper, and packet handling
- `tests/` — unit tests (planned)
- `examples/` — minimal demo programs
- `Makefile` — build client and server executables

## Getting Started

1. Run `make` to build client and server

```bash
make
```

2. Run server:

```bash
./bin/server
```

3. Run client (in another terminal):

```bash
./bin/client
```

4. TODO: Client will send a simple packet to the server, which prints it.

## Next Steps

- Implement UDP socket send/receive functions
- Implement packet encode/decode
- Implement main client/server logic to send and print packets

_Author:_ Ata  
_Started:_ August 2025

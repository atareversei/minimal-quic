#include <stdio.h>
#include "udp.h"

int main() {
    printf("Server started\n");
    int i = udp_socket_create();
    printf("%d\n", i);

    // TODO:
    // 1. Create and bind UDP socket
    // 2. Loop receiving packets
    // 3. Decode received data into quic_packet_t
    // 4. Print packet fields
    // 5. Cleanup on exit

    return 0;
}
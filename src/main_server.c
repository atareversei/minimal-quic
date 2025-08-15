#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "udp.h"
#include "packet.h"

// TODO: ACK packet number is just pkt.packet_number + 1; real QUIC tracks per-connection state.
// TODO: Only handles one packet at a time per connection; multiple in-flight packets are not tracked.
// TODO: No retransmission, congestion control, or connection timeout handling.
// TODO: Single-threaded; a real server would need async I/O or threads for multiple clients.
// TODO: Payload is printed as string; binary payloads may contain null bytes and need careful handling.

const char *SERVER_IP = "0.0.0.0";
const int SERVER_PORT = 4546;
const int MAX_BUF_SIZE = 1500;

int main() {
  printf("Server started\n");
  const int sock = udp_socket_create();
  if (sock < 0) {
    fprintf(stderr, "socket not created");
    return 1;
  }

  if ((udp_bind(sock, SERVER_IP, SERVER_PORT)) < 0) {
    fprintf(stderr, "socket did not bind");
  }

  while (1) {
    char buf[MAX_BUF_SIZE];
    char src_ip[INET_ADDRSTRLEN];
    int src_port;

    const int len = udp_recv(sock, buf, sizeof(buf), src_ip, &src_port);

    if (len <= 0) continue;

    quic_packet_t quic_pkt;
    if (packet_decode(buf, len, &quic_pkt) < 0) {
      fprintf(stderr, "failed to decode QUIC packet");
      return 1;
    }

    printf("Source ID: %lu", quic_pkt.scid);
    printf("Destination ID: %lu", quic_pkt.dcid);
    printf("Packet Number: %u", quic_pkt.packet_number);
    printf("Data: %.*s", quic_pkt.payload_len, quic_pkt.payload);

    quic_packet_t ack_pkt = {0};
    ack_pkt.dcid = quic_pkt.scid;
    ack_pkt.scid = quic_pkt.dcid;
    ack_pkt.packet_number = quic_pkt.packet_number + 1;
    const char *ack_msg = "ACK";
    ack_pkt.payload_len = strlen(ack_msg);
    memcpy(ack_pkt.payload, ack_msg, ack_pkt.payload_len);

    char send_buf[MAX_BUF_SIZE];
    const int send_len = packet_encode(&ack_pkt, send_buf, sizeof(send_buf));
    udp_send(sock, send_buf, send_len, src_ip, src_port);
  }

  return 0;
}

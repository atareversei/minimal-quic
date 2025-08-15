#include <stdio.h>
#include <string.h>
#include <netinet/in.h>

#include "packet.h"
#include "udp.h"

const char *SERVER_IP = "192.168.1.1";
const int SERVER_PORT = 4546;

int main() {
  printf("Client started\n");

  int sock = udp_socket_create();
  if (sock < 0) {
    fprintf(stderr, "socket not created");
    return 1;
  }

  quic_packet_t pkt = {0};
  pkt.dcid = 0x1234;
  pkt.scid = 0x5678;
  pkt.packet_number = 1;
  const char *msg = "Hello";
  pkt.payload_len = strlen(msg);
  memcpy(pkt.payload, msg, pkt.payload_len);

  char send_buf[MAX_PAYLOAD_SIZE];
  int send_len = packet_encode(&pkt, &send_buf, sizeof(send_buf));
  udp_send(sock, &send_buf, send_len, SERVER_IP, SERVER_PORT);
  printf("Sent Hello to %s:%d", SERVER_IP, SERVER_PORT);

  char *rcv_buf[MAX_PAYLOAD_SIZE];
  char *src_ip[INET_ADDRSTRLEN];
  int src_port;
  int len = udp_recv(sock, rcv_buf, sizeof(rcv_buf), src_ip, &src_port);
  if (len <= 0) {
    fprintf(stderr, "no response received\n");
    return 1;
  }

  quic_packet_t ack_pkt;
  if (packet_decode(rcv_buf, len, &ack_pkt) < 0) {
    fprintf(stderr, "Failed to decode ACK\n");
    return 1;
  }

  printf("Received ACK from %s:%d\n", src_ip, src_port);
  printf("  DCID: %llu\n", ack_pkt.dcid);
  printf("  SCID: %llu\n", ack_pkt.scid);
  printf("  Packet Number: %u\n", ack_pkt.packet_number);
  printf("  Payload: %.*s\n", (int)ack_pkt.payload_len, ack_pkt.payload);

  return 0;

  return 0;
}

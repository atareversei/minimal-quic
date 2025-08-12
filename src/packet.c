#include "packet.h"
#include <string.h>
#include <arpa/inet.h>

size_t packet_encode(const quic_packet_t *pkt, uint8_t *buf, size_t bufsize) {
  if (bufsize < 8 + 4 + pkt->payload_len) {
    return 0;
  }

  uint64_t conn_id_n = htobe64(pkt->connection_id);
  memcpy(buf, &conn_id_n, 8);

  uint32_t pkt_num_n = htonl(pkt->packet_number);
  memcpy(buf + 8, &pkt_num_n, 4);

  memcpy(buf + 12, pkt->payload, pkt->payload_len);

  return 12 + pkt->payload_len;
}

int packet_decode(const uint8_t *buf, size_t len, quic_packet_t *pkt) {
  if (len < 12) {
      return -1;
  }
  uint64_t conn_id_n;
  memcpy(&conn_id_n, buf, 8);
  pkt->connection_id = be64toh(conn_id_n);

  uint32_t pkt_num_n;
  memcpy(&pkt_num_n, buf + 8, 4);
  pkt->packet_number = ntohl(pkt_num_n);

  pkt->payload_len = len - 12;
  if (pkt->payload_len > MAX_PAYLOAD_SIZE) {
    return -1;
  }
  memcpy(pkt->payload, buf + 12, pkt->payload_len);
  return 0;
}
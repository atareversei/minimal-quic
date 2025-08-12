#ifndef PACKET_H
#define PACKET_H

#include <stddef.h>
#include <stdint.h>

#define MAX_PAYLOAD_SIZE 1024

typedef struct {
  uint64_t connection_id;
  uint32_t packet_number;
  uint8_t payload[MAX_PAYLOAD_SIZE];
  size_t payload_len;
} quic_packet_t;

size_t packet_encode(const quic_packet_t *pkt, uint8_t *buf, size_t bufsize);
int packet_decode(const uint8_t *buf, size_t len, quic_packet_t *pkt);

#endif
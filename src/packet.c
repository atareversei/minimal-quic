#include "packet.h"
#include <string.h>
#include <arpa/inet.h>

// TODO: The minimal packet only includes DCID, SCID, packet number, and payload.
// TODO: No variable-length encoding, encryption, or authentication is implemented.
// TODO: Payload length is inferred from UDP packet length; real QUIC encodes length explicitly.
// TODO: No validation of packet numbers across multiple packets per connection.

size_t packet_encode(const quic_packet_t *pkt, uint8_t *buf, size_t bufsize) {
    if (bufsize < 8 + 8 + 4 + pkt->payload_len) {
        return 0;
    }

    const uint64_t dcid_n = htobe64(pkt->dcid);
    memcpy(buf, &dcid_n, 8);

    const uint64_t scid_n = htobe64(pkt->scid);
    memcpy(buf + 8, &scid_n, 8);

    const uint32_t pkt_num_n = htonl(pkt->packet_number);
    memcpy(buf + 16, &pkt_num_n, 4);

    memcpy(buf + 20, pkt->payload, pkt->payload_len);

    return 20 + pkt->payload_len;
}

int packet_decode(const uint8_t *buf, size_t len, quic_packet_t *pkt) {
    if (len < 20) {
        return -1;
    }

    uint64_t dcid_n, scid_n;
    memcpy(&dcid_n, buf, 8);
    memcpy(&scid_n, buf + 8, 8);
    pkt->dcid = be64toh(dcid_n);
    pkt->scid = be64toh(scid_n);

    uint32_t pkt_num_n;
    memcpy(&pkt_num_n, buf + 16, 4);
    pkt->packet_number = ntohl(pkt_num_n);

    pkt->payload_len = len - 20;
    if (pkt->payload_len > MAX_PAYLOAD_SIZE) {
        return -1;
    }
    memcpy(pkt->payload, buf + 20, pkt->payload_len);

    return 0;
}

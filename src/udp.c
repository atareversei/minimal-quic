#include "udp.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

int udp_socket_create() {
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) {
    perror("socket creation failed");
    return -1;
  }
  return sock;
}

int udp_bind(int sock, const char *ip, int port) {
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = inet_addr(ip);

  if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    perror("bind failed");
    return -1;
  }
  return 0;
}

int udp_send(int sock, const void *buf, size_t len, const char *ip, int port) {
  struct sockaddr_in dest_addr;
  memset(&dest_addr, 0, sizeof(dest_addr));
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons(port);
  dest_addr.sin_addr.s_addr = inet_addr(ip);

  ssize_t sent = sendto(sock, buf, len, 0, (struct sockaddr*)&dest_addr, sizeof(dest_addr));
  if (sent < 0) {
    perror("sendto failed");
    return -1;
  }
  return (int)sent;
}

int udp_recv(int sock, void *buf, size_t maxlen, char *src_ip, int *src_port) {
  struct sockaddr_in src_addr;
  socklen_t addrlen = sizeof(src_addr);
  ssize_t received = recvfrom(sock, buf, maxlen, 0, (struct sockaddr*)&src_addr, &addrlen);
  if (received < 0) {
    perror("recvfrom failed");
    return -1;
  }
  if (src_ip) {
    // TODO: not thread-safe
    strcpy(src_ip, inet_ntoa(src_addr.sin_addr));
  }
  if (src_port) {
    *src_port = ntohs(src_addr.sin_port);
  }
  return (int)received;
}

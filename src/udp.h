#ifndef UDP_H
#define UDP_H

#include <stddef.h>

int udp_socket_create();
int udp_bind(int sock, const char *ip, int port);
int udp_send(int sock, const void *buf, size_t len, const char *ip, int port);
int udp_recv(int sock, void *buf, size_t maxlen, char *src_ip, int *src_port);

#endif
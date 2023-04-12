#ifndef SOCKET_SERVER_H
#define SOCKET_SERVER_H

#include <arpa/inet.h>

typedef void (*callback)(char* message, int len);

typedef struct {
	int s;
	char* buf;
	int buf_len;
	callback socket_cb;
	struct sockaddr_in server;
} udp_client;

int socket_client_loop(udp_client* cl);
int socket_client_stop(udp_client* cl);
int socket_client_send(udp_client* cl, char* message, int len);

int sink_client_start(const char* ip, const int port, udp_client* cl);
int socket_client_start(const char* ip, const int port, udp_client* cl);

#endif
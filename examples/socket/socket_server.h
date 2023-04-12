#ifndef SOCKET_SERVER_H
#define SOCKET_SERVER_H

#include <arpa/inet.h>

typedef void (*callback)(char* message, int len);

typedef struct {
	int s;
	char* buf;
	int buf_len;
	callback socket_cb;
	int maxfdp;
} udp_server;

int socket_server_loop(udp_server* serv);
int socket_server_stop(udp_server* serv);
int socket_server_send(udp_server* serv, char* message, int len);
int socket_server_start(const char* ip, const int port, udp_server* serv);

#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sys/socket.h>
#include <unistd.h>

#include "socket_client.h"

int socket_client_send(udp_client* cl, char* message, int len) {
    int rc, server_address_size;
    
    server_address_size = sizeof(cl->server);

    rc = send(cl->s, message, len, 0);

    return rc;
}

int socket_client_loop(udp_client* cl) {
    int len, server_address_size;
    server_address_size = sizeof(cl->server);

    len = recv(cl->s, cl->buf, cl->buf_len, 0); // block
    if(len < 0) {
        printf("can not load message, maybe check your connection? \n");
        return len;
    }
    
    printf("received %d bytes on socket\n", len);
    (*cl->socket_cb)(cl->buf, len);

    return len;
}

int socket_client_stop(udp_client* cl) {
    close(cl->s);
    free(cl->buf);
}

int sink_client_start(const char* ip, const int port, udp_client* cl) {
    int s = socket_client_start(ip, port, cl);
    if(s < 0) {
        return s;
    }

    return cl->s;
}

int socket_client_start(const char* ip, const int port, udp_client* cl) {
    int s, namelen;

    if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        printf("failed to set up socket\n");
        return -1;
    }

    memset((char *) &cl->server, 0, sizeof(cl->server));

    cl->server.sin_family = AF_INET;
    cl->server.sin_port = htons(port);

    if (inet_aton(ip , &cl->server.sin_addr) == 0) {
        printf("inet_aton() failed\n");
        return -2;
    }

    if(connect(s, (struct sockaddr *) &cl->server, sizeof(struct sockaddr)) < 0) {
        printf("Failed to connect to remote server!\n");
        return -3;
    }

    printf("socket client connected to %s:%d\n", ip, port);
    
    cl->buf_len = 4096;
    cl->buf = (char*) malloc(sizeof(char) * cl->buf_len);
    cl->s = s;

    return s;
}
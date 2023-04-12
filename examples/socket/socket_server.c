#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <pthread.h> //for threading , link with lpthread

#include "socket_server.h"

#define MAXLINE         4096

char                    printd_buf[2048];
fd_set                  rset;
int                     nready, udpfd;
struct sockaddr_in      cliaddr, servaddr;

int socket_server_send(udp_server* udps, char* message, int len) {
    int sockfd, rc, client_address_size;

    if (cliaddr.sin_port != 0) {
        client_address_size = sizeof(cliaddr);
        rc = sendto(udpfd, message, len, 0, (struct sockaddr *)&cliaddr, client_address_size);
    } else {
        printf("cannot forward message - no destination on socket \n");
    }

    return rc;
}

int socket_server_loop(udp_server* udps) {
    // set fds in readset
    FD_SET(udps->s, &rset);

    // select the ready descriptor
    nready = select(udps->maxfdp, &rset, NULL, NULL, NULL);
    
    // ..
    // .. handle other sockets

    if (FD_ISSET(udps->s, &rset)) { // if udp socket is readable receive the message
        int len = sizeof(cliaddr);
        bzero(udps->buf, sizeof(udps->buf));
        int n = recvfrom(udps->s, udps->buf, udps->buf_len, 0, (struct sockaddr*) &cliaddr, &len);
        printf("received %d bytes on socket - set client address to %d\n", n, cliaddr.sin_port);
        (*udps->socket_cb)(udps->buf, n);
    }

    return 1;
}

int socket_server_stop(udp_server* udps) {
    close(udps->s);
    free(udps->buf);
}

int socket_server_start(const char* ip, const int port, udp_server* udps) {
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(port);
 
    udpfd = socket(AF_INET, SOCK_DGRAM, 0);
    // binding server addr structure to udp sockfd
    bind(udpfd, (struct sockaddr*)&servaddr, sizeof(servaddr));
 
    // clear the descriptor set
    FD_ZERO(&rset);
 
    // get maxfd
    udps->maxfdp = udpfd + 1;

    udps->buf_len = MAXLINE;
    udps->buf = (char*) malloc(sizeof(char) * udps->buf_len);
    udps->s = udpfd;

    printf("socket server started on port %d \n", htons(servaddr.sin_port));
    
    return udpfd;
}

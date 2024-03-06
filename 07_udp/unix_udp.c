

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define UDP_APP_RECV_BUFFER_SIZE 128

int main(int argc, char *argv[]) {

    int connfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(connfd == -1) {
        printf("socket failed\n");
        return -1;
    }

    struct sockaddr_in localaddr, clientaddr;
    memset(&localaddr, 0, sizeof(struct sockaddr_in));

    localaddr.sin_family = AF_INET;
    localaddr.sin_port = htons(8888);
    localaddr.sin_addr.s_addr = htonl(INADDR_ANY);

    bind(connfd, (struct sockaddr*)&localaddr, sizeof(struct sockaddr));

    socklen_t addrlen = sizeof(struct sockaddr);
    char buffer[UDP_APP_RECV_BUFFER_SIZE] = {0};
    while(1) {
        if(recvfrom(connfd,buffer,UDP_APP_RECV_BUFFER_SIZE, 0,(struct sockaddr*)&clientaddr,&addrlen) < 0) {
            continue;
        } else {
            printf("recvfrom:%s : %d   data:%s\n",
                inet_ntoa(clientaddr.sin_addr),ntohs(clientaddr.sin_port),buffer);

            sendto(connfd, buffer, strlen(buffer), 0, (struct sockaddr*)&clientaddr, sizeof(clientaddr));
            
        }
    }

    close(connfd);
}
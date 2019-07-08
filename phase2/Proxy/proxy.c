#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>

/*
for connection_handler handler

char buffer[1024];
strcpy(buffer, "Message from proxy");
write(sockfd, buffer, strlen(buffer));
close(sockfd)
*/

#define port 8000

void get_host(char headers[]){
  int i;
  for (i = 0; i < strlen(headers); i++) {
    if (strcmp(&headers[i], "H") == 0) {
      //printf("%s\n", "Ran");
      printf("%c\n", headers[i]+6);
    }
  }
}

void sock_send(const char *text, int sockfd){
  //char buffer[6000];
  //strcpy(buffer, text);
  write(sockfd, text, strlen(text));
  //memset(&buffer, '\0', sizeof(buffer));
}

void connection_handler(int sockfd){
  int read_size;
  char readbuffer[1024];
  char headers[4000];
  printf("%s\n", "Connection");
  while (1){
    if ((read_size = recv(sockfd, readbuffer, 2000, 0)) > 0) {
      strcat(headers, readbuffer);
    }
    get_host(headers);
    sock_send(headers, sockfd);
    close(sockfd);
    memset(&readbuffer, '\0', sizeof(readbuffer));
    memset(&headers, '\0', sizeof(headers));
    return;
  }
}

int main(int argc, char const *argv[]) {
  int listenfd = 0, connfd = 0;

  struct sockaddr_in serv_addr;

  char sendBuff[1025];

  listenfd = socket(AF_INET, SOCK_STREAM, 0);

  memset(&serv_addr, '0', sizeof(serv_addr));
  memset(sendBuff, '0', sizeof(sendBuff));

  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  serv_addr.sin_port = htons(port);

  bind(listenfd, (struct sockaddr*)&serv_addr,sizeof(serv_addr));
  printf("%s\n", "Binded");

  /*
  int setsockopt(int socket, int level, int option_name,
const void *option_value, socklen_t option_len);
  */
  int error;
  int sockopt = 1;
  int fd = setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &error, sizeof(sockopt));
  printf("%d\n", fd);
  printf("%d\n", error);

  if(listen(listenfd, 10) == -1){
      printf("Failed to listen\n");
      return -1;
  }

  while (1){
    connfd = accept(listenfd, (struct sockaddr*)NULL ,NULL);
    connection_handler(connfd);
  }
  return 0;
}

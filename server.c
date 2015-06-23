#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>//socket函数
#include <netinet/in.h>// 定义数据结构sockaddr_in
#include <arpa/inet.h>//ip地址转换函数

#define SERV_PORT 9877
#define WAIT_COUNT 10
void 
str_echo(){
	ssize_t n;
	char buf[MAXLINE];

	again:
	while((n = read(sockfd,buf,MAXLINE)) > 0)
		write(sockfd,buf,n);

	if (n < 0 && errno == EINTR)
		goto again;
	else if (n < 0)
		printf("read error\n");
	else 
		printf("client closed\n");
}
/*
 *功能：自定义的信号处理函数
 *
 *
 **/
typedef void (SigFunc)(int);

SigFunc * Signal(int signo, SigFunc * func){

	struct sigaction act, oact;
	act.sa_handler = func;
	// 信号集设置为空，不阻塞信号
	sigemptyset(&act.sa_mask);

	act.sa_flags = 0;//可以设置flags

	//信号处理
	if (signo == SIGALRM){
		//中断系统调用
#ifdef SA_INTERRUPT	
		act.flags |= SA_INTERRUPT；
#endif
	}else{
		//重启系统调用
#ifdef SA_RESTART	
		act.flags |= SA_RESTART;
#endif
	}

	if(sigaction(signo,&act,&oact)< 0){
		return SIG_ERR;	
	}
	return oact.sa_handler;
}
/**
 *功能：信号处理函数
 *
 *
 */
void sig_chld(int signo){
	pid_t pid;
	int stat;

	// 状态不改变直接返回0
	while((pid = waitpid(-1,&stat,WNOHANG)) > 0)
		printf("%d child terminated\n");
}

int main(int argc, char *argv[]){
	int listen_fd,conn_fd;
	struct sockaddr_in server_addr,client_addr;
	pid_t childpid ;
	//  长度
	socklen_t len = sizeof(struct sockaddr_in);

	listen_fd = socket(AF_INET,SOCK_STREAM,0);
	if (listen_fd == -1)
	{
		perror("socket failed\n");	
		return;
	}

	bzero(&server_addr,len);
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons(SERV_PORT);

	bind(listen_fd,(struct sockaddr*)&server_addr,len);

	listen(listen_fd,WAIT_COUNT);
// 处理信号SIGCHLD

	for(;;){
		//接受连接
		conn_fd = accept(listen_fd,(struct sockaddr *)&client_addr,&len);	
		if (conn_fd < 0)
		{
			// 处理中断,重新启动系统调用
			if (errno == EINTR)
				continue;
			else{
				printf("accept error\n");		
				return -1;
			}
		}
		printf("新链接，创建一个子进程\n");
		// 创建子进程
		if ((childpid = fork()) == 0){// child
			close(listen_fd);	
			printf("子进程%d创建\n",getpid());
#if 1
			// 子进程的工作 do something
			char content[4096];
			read(conn_fd,content,sizeof(content));
#endif
			printf("子进程%d结束\n",getpid());
			close(conn_fd);
			exit(0);
		}
		// 父进程
		close(conn_fd);
	}

	return 0;
}

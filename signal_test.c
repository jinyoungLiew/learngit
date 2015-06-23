#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>

//ctrl + \产生SIGQUIT信号

static void sig_quit(int signo){
	printf("SIQQUIT is caught\n");
}


int main()
{
	sigset_t new,old,pend;

	// 安装信号
	if (signal(SIGQUIT,sig_quit) == SIG_ERR){
		perror("signal");	
		exit(1);
	}

	if (sigemptyset(&new) < 0)
		perror("sigempty error");
	if (sigaddset(&new,SIGQUIT) < 0)
		perror("sig addset error");
	
	//设置信号屏蔽字
	if (sigprocmask(SIG_SETMASK,&new,&old) < 0){
		perror("sig promask");	
	    exit(1);
	}
	
	sleep(5);
	
	if (sigpending(&pend) < 0)
		perror("sig pend");

	if (sigismember(&pend,SIGQUIT)<0){
		perror("sig pend");	
	}

	// 复位后，按ctrl + \可以捕捉到信号
	if (sigprocmask(SIG_SETMASK,&old,NULL) < 0){
		perror("sigprocmask");	
		exit(1);
	}

	printf("SIQQUIT unblocked\n");
	printf("now try ctrl + \\ \n");
	sleep(5);

	return 0;
}

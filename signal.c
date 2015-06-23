#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

//SIGQUIT(ctrl+\触发)

static void sig_quit(int signo)
{
    printf("SIGQUIT is caught\n");
}
int main()
{
	sigset_t new,old,pend;
	// 安装信号
    if (signal(SIGQUIT, sig_quit) == SIG_ERR)
    {
        perror("signal");
        exit(1);
    }
   
    if (sigemptyset(&new) < 0)
        perror("sigemptyset");

    if (sigaddset(&new, SIGQUIT) < 0)
        perror("sigaddset");
   
    if (sigprocmask(SIG_SETMASK, &new, &old) < 0)
    {
        perror("sigprocmask");
        exit(1);
    }
    printf("SIGQUIT is blocked ");
    printf("Now try Ctrl \n");
    sleep(5);
  if (sigpending(&pend) < 0)
        perror("sigpending");
    if (sigismember(&pend, SIGQUIT))
        printf("SIGQUIT pending ");
   
    if (sigprocmask(SIG_SETMASK, &old, NULL) < 0)
    {
        perror("sigprocmask");
        exit(1);
    }
    printf(" SIGQUIT unblocked ");
    printf("Now try Ctrl \n");
    sleep(5);

    return 0;
}

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <libgen.h>
#include <signal.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <netinet/in.h>  
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include "utils.h"
#include "log.h"

void _Assert (char* name, char* strFile, unsigned uLine) 
{           
    dump(L_ERR, "Assertion failed: %s, %s, line %u", name, strFile, uLine);
    abort();
}          

int daemon_init(void) 
{
    pid_t pid;
    if((pid = fork())< 0) {
            return ERR;
    } else if(pid > 0) {
            dump(L_ERR, "parent process exit.");
            exit(0);
    }
    setsid();                         
    if((pid = fork()) < 0) {
            return ERR;
    } else if(pid > 0) {
            dump(L_INFO, "child process exit.");
            exit(0);                
    }

    dump(L_INFO, "Daemon Start Working.");
    umask(0);                      

    return OK;
}

/* for single process */
int lock_fd;

int single_process(char *process_name)
{       
    char lockfile[128];
    
    snprintf(lockfile, sizeof(lockfile), "/var/lock/%s.pid", basename(process_name));
    
    lock_fd = open(lockfile, O_CREAT|O_WRONLY, 00200);
    
    if (lock_fd <= 0) {
        dump(L_ERR, "Cant fopen file %s for %s\n", lockfile, strerror(errno)); 
        return -1;
    }                                                                                                                     
    /* F_LOCK will hang until unlock, F_TLOCK will return asap */
    int ret = lockf(lock_fd, F_TLOCK, 0);
    
    if (ret == 0) {
        return 0;
    } else {
        dump(L_ERR, "Cant lock %s for %s\n", lockfile, strerror(errno));
        return -1;
    }
}

void sig_pipe_handler(int sig) {
    return;
}
void sig_init(void)
{
    /*
     *		block 
     *          SIGTERM SIGHUP SIGPIPE
     *
     *      handler
     *          SIGALRM
    */
    sigset_t intmask;

    sigemptyset(&intmask);
    sigaddset(&intmask,SIGTERM);
    sigprocmask(SIG_BLOCK,&intmask,NULL);

    sigemptyset(&intmask);
    sigaddset(&intmask,SIGHUP);  
    sigprocmask(SIG_BLOCK,&intmask,NULL);

    struct sigaction act2;

    act2.sa_handler = sig_pipe_handler;
    act2.sa_flags = SA_INTERRUPT;
    sigemptyset(&act2.sa_mask);
    sigaddset(&act2.sa_mask, SIGPIPE);

    sigaction(SIGPIPE, &act2, 0);
}

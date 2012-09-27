#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
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

#include "log.h"
#include "mysqlpcap.h"
#include "address.h"
#include "packet.h"
#include "hash.h"

#define SIZE_IP         16
#define SIZE_ETHERNET   14
#define ETHER_ADDR_LEN  6
#define HOSTNAME_LEN    128

#define PKT_TYPE_TCP    1
#define PKT_TYPE_UDP    2

#define OUTPUT_INTERVAL 300

#define CAPLEN 65535

uint8_t GoutputFlg = 0;

void switch_flg(int sig) {
    if (SIGALRM == sig) GoutputFlg = 1;
}

int daemon_init(void) {

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

void 
sig_pipe_handler(int sig) {
        return;
}      

int lock_fd;

int 
single_process(char *process_name)
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

void 
sig_init(void)
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

    signal(SIGALRM, switch_flg);
}

void 
init(MysqlPcap *mp) {
    mp->mysqlPort = 3306;
    snprintf(mp->netDev, sizeof(mp->netDev), "%s", "any");
    if (mp->address) {
        dump(L_WARN, "address %s", mp->address);
        mp->al = parse_addresses(mp->address);
    } else {
        mp->al = get_addresses();
    }
    mp->hash = hash_new();
}

int
main (int argc, char **argv) {

    log_init("mysqlpcap", NULL, ".log");

    char usage[] = "Usage: \n\tmysqlstat -p [port] mysql port default 3306\n"
                    "\t -d daemon default yes\n \t -f [filename] default tty\n"
                    "\t -i [dev]\n"
                    "\t -l address1,address2\n";

    MysqlPcap *mp = calloc(1, sizeof(*mp));

    if (NULL == mp) return ERR;

    char ch;
    while (-1 != (ch = getopt(argc, argv, "p:df:k:i:l:"))) {
        switch (ch) {
            case 'p' :
                mp->mysqlPort = atoi(optarg);
                break;
            case 'd' :
                daemon_init();
                break;
            case 'f':
                snprintf(mp->logfile, sizeof(mp->logfile), "%s", optarg);
                break;
            case 'k' :
                snprintf(mp->keyWord, sizeof(mp->keyWord), "%s", optarg); 
                break; 
            case 'i' :
                snprintf(mp->netDev, sizeof(mp->netDev), "%s", optarg); 
                break; 
            case 'l':
                mp->address = malloc(strlen(optarg) + 1);
                snprintf(mp->address, strlen(optarg) + 1, "%s", optarg);
                break;
            case 'h' :
            default :
                printf("%s", usage);
                return ERR;
        }
    }

    init(mp);

    if (0 != single_process(argv[0])) return ERR; 

    sig_init();

    start_packet(mp);

    free(mp);

    dump(L_ERR, "why go here ?");
    return OK;
}


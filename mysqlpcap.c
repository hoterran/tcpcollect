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
#include "local-addresses.h"
#include "process-packet.h"
#include "stats-hash.h"

typedef unsigned int uint;
typedef unsigned int uint32;
typedef unsigned char uchar;
typedef unsigned long ulong;

#define uint3korr(A)    (uint32) (((uint32) ((uchar) (A)[0])) +\
    (((uint32) ((uchar) (A)[1])) << 8) +\
    (((uint32) ((uchar) (A)[2])) << 16))


#define SIZE_IP         16
#define SIZE_ETHERNET   14
#define ETHER_ADDR_LEN  6
#define HOSTNAME_LEN    128

#define PKT_TYPE_TCP    1
#define PKT_TYPE_UDP    2

#define OUTPUT_INTERVAL 300


#define CAPLEN 65535

/* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type;                 /* IP? ARP? RARP? etc */
};

#define SLL_HDR_LEN     16              /* total header length */
#define SLL_ADDRLEN     8               /* length of address field */
        
struct sll_header {                                                                                                           
    u_int16_t       sll_pkttype;        /* packet type */
    u_int16_t       sll_hatype;         /* link-layer address type */
    u_int16_t       sll_halen;          /* link-layer address length */
    u_int8_t        sll_addr[SLL_ADDRLEN];  /* link-layer address */
    u_int16_t       sll_protocol;       /* protocol */
};

/* IP header */
struct sniff_ip {
    u_char ip_vhl;		/* version << 4 | header length >> 2 */
    u_char ip_tos;		/* type of service */
    u_short ip_len;		/* total length */
    u_short ip_id;		/* identification */
    u_short ip_off;		/* fragment offset field */
    #define IP_RF 0x8000		/* reserved fragment flag */
    #define IP_DF 0x4000		/* dont fragment flag */
    #define IP_MF 0x2000		/* more fragments flag */
    #define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
    u_char ip_ttl;		/* time to live */
    u_char ip_p;		/* protocol */
    u_short ip_sum;		/* checksum */
    struct in_addr ip_src,ip_dst; /* source and dest address */
};

#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
struct sniff_tcp {
    uint16_t th_sport;	/* source port */
    uint16_t th_dport;	/* destination port */
    uint32_t th_seq;	/* sequence number */
    uint32_t th_ack;	/* acknowledgement number */

    u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;		/* window */
    u_short th_sum;		/* checksum */
    u_short th_urp;		/* urgent pointer */
};

const struct sll_header *sllhdr;

const struct sniff_ethernet *ethernet;  /* The ethernet header */
const struct sniff_ip *iphdr;           /* The IP header */
const struct sniff_tcp *tcphdr;         /* The TCP header */
const char *payload;                    /* Packet payload */

u_int size_iphdr;
u_int size_tcphdr;

uint8_t GoutputFlg = 0;

void switch_flg(int sig) {
    if (SIGALRM == sig) GoutputFlg = 1;
}

int daemon_init(void) {

    pid_t pid;
    if((pid = fork())< 0) {
            return ERR;
    } else if(pid > 0) {
            alog(L_INFO, "parent process exit.");
            exit(0);
    }
    setsid();                         
    if((pid = fork()) < 0) {
            return ERR;
    } else if(pid > 0) {
            alog(L_INFO, "child process exit.");
            exit(0);                
    }

    alog(L_INFO, "Daemon Start Working.");
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
        printf("Cant fopen file %s for %s\n", lockfile, strerror(errno)); 
        return -1;
    }                                                                                                                     
    /* F_LOCK will hang until unlock, F_TLOCK will return asap */
    int ret = lockf(lock_fd, F_TLOCK, 0);
    
    if (ret == 0) {
        return 0;
    } else {
        printf("Cant lock %s for %s\n", lockfile, strerror(errno));
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
    mp->al = get_addresses();
    mp->hash = hash_new();
}

int
main (int argc, char **argv) {

    char usage[] = "Usage: \n\tmysqlstat -p [port] mysql port default 3306\n"
                    "\t -d daemon default yes\n \t -f [filename] default tty\n"
                    "\t -i [dev]\n";

    MysqlPcap *mp = calloc(1, sizeof(*mp));

    if (NULL == mp) return ERR;

    init(mp);

    char ch;
    while (-1 != (ch = getopt(argc, argv, "p:df:k:i:"))) {
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
            case 'h' :
            default :
                printf("%s", usage);
                return ERR;
        }
    }

    if (0 != single_process(argv[0])) return ERR; 

    sig_init();

    start_packet(mp);

    free(mp);

    alog(L_INFO, "why go here ?");
    return OK;
}


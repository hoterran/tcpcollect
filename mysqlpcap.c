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
#include <hiredis/hiredis.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

typedef unsigned int uint;
typedef unsigned int uint32;
typedef unsigned char uchar;
typedef unsigned long ulong;

#define uint3korr(A)    (uint32) (((uint32) ((uchar) (A)[0])) +\
    (((uint32) ((uchar) (A)[1])) << 8) +\
    (((uint32) ((uchar) (A)[2])) << 16))

#define OK      (0)
#define ERR     (-1)
#define PEND    (1)

#define SIZE_IP         16
#define SIZE_ETHERNET   14
#define ETHER_ADDR_LEN  6
#define HOSTNAME_LEN    128

#define PKT_TYPE_TCP    1
#define PKT_TYPE_UDP    2

#define OUTPUT_INTERVAL 300

#define L_ERROR 0
#define L_WARN  1
#define L_INFO  2

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

typedef struct statArgTag {
uint8_t pktType;
} StatArg;

typedef struct _MysqlPcap {
    char        hostname[HOSTNAME_LEN];
    pcap_t      *pd;
    int         mysqlPort;
    char        filter[10240];
    char        netDev[10];
    bpf_u_int32 netmask;
    bpf_u_int32 localnet;
    char        logfile[256];
    char        keyWord[256];
} MysqlPcap;

uint8_t GoutputFlg = 0;

void
alog (int level, char *fmt, ...)
{
    char levelStr[][32] = {"ERROR", "WARN", "INFO"};
    char head[128], body[10240],logname[128];
    struct tm tm;
    time_t t;
    va_list ap;
    FILE *fp;

    time(&t);
    localtime_r(&t, &tm);

    snprintf(head, sizeof(head),"%d:%02d:%02d %s", 
        tm.tm_hour, tm.tm_min, tm.tm_sec, levelStr[level]);
    va_start(ap, fmt);
    vsnprintf(body, sizeof(body), fmt, ap);
    va_end(ap);

    snprintf(logname, sizeof(logname), "/tmp/webdump-agent%d-%02d-%02d.log",
        1900+tm.tm_year, tm.tm_mon+1, tm.tm_mday);
    fp = fopen(logname, "a+");
    if (NULL == fp) {
        printf("[%s] %s\n\n", head, body);
    } else {
        fprintf(fp, "[%s] %s\n\n", head, body);
        fclose(fp);
    }

    return;
}

void 
pkt_stat (MysqlPcap* mp, const struct pcap_pkthdr *h, const u_char *s) {

    struct tm	*tm;
    char		src_ip[16], dst_ip[16];
    uint16_t	src_port, dst_port;

    //use any device(bond?),  not ethernet, but sll protocol
    //ethernet = (struct sniff_ethernet*)(s);
    //sllhdr = (struct sll_header*)(s);

    iphdr = (struct sniff_ip *)(s + SIZE_ETHERNET);
    //iphdr = (struct sniff_ip *)(s + SLL_HDR_LEN);
    size_iphdr = IP_HL(iphdr)*4;
    if (size_iphdr < 20) {
        alog(L_WARN, "   * Invalid IP header length: %u bytes", size_iphdr);
        return;	
    }

    tcphdr = (struct sniff_tcp *)(s + SIZE_ETHERNET + size_iphdr);
    //tcphdr = (struct sniff_tcp *)(s + SLL_HDR_LEN + size_iphdr);
    size_tcphdr = TH_OFF(tcphdr)*4;

    if (size_tcphdr < 20) {
        alog(L_WARN, "   * Invalid TCP header length: %u bytes\n", size_tcphdr);
        return;
    }

    inet_ntop(AF_INET, (void *)&(iphdr->ip_src), src_ip, SIZE_IP);
    inet_ntop(AF_INET, (void *)&(iphdr->ip_dst), dst_ip, SIZE_IP);
    src_port = ntohs(tcphdr->th_sport);
    dst_port = ntohs(tcphdr->th_dport);

    char* payload = (char*)(s + SIZE_ETHERNET + size_iphdr + size_tcphdr);
    //char* payload = s + SLL_HDR_LEN + size_iphdr + size_tcphdr;

    /* start mysql protocol */
    ulong packet_length = uint3korr(payload);

    char *commandSql = payload + 4;
    int command = commandSql[0];
    commandSql[packet_length] = '\0';

    printf("%ld - %ld [%d] %s\n\n", 
        h->ts.tv_sec, h->ts.tv_usec, command, commandSql + 1);

    return;
}

int 
set_filter (MysqlPcap *mp) {

    struct bpf_program  fcode;
    char filter[256];

    snprintf(filter, sizeof(filter), 
        "dst port %d and tcp[tcpflags] & (tcp-push) != 0", mp->mysqlPort);

    if (pcap_compile(mp->pd, &fcode, filter, 0, mp->netmask) < 0) {
        alog(L_WARN, "pcap_compile failed: %s", pcap_geterr(mp->pd));
        pcap_freecode(&fcode);
        return ERR;
    }

    if (pcap_setfilter(mp->pd, &fcode) < 0) {
        alog(L_WARN, "pcap_setfilter failed: %s", pcap_geterr(mp->pd));
        pcap_freecode(&fcode);
        return ERR;
    }

    pcap_freecode(&fcode);
    return OK;
}

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

int single_process(char *process_name)
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
    snprintf(mp->netDev, sizeof(mp->netDev), "%s", "eth0");
}

int
main (int argc, char **argv) {

    char usage[] = "Usage:\n\tmysqlstat -p [port] mysql port default 3306\n"
                    "\t -d daemon default yes\n \t -f [filename] default tty\n"
                    "\t -i [dev]\n";

    char ebuf[PCAP_ERRBUF_SIZE];

    u_char *pkt_data = malloc(CAPLEN);
    struct pcap_pkthdr *pcap_pkthdr = malloc(sizeof(struct pcap_pkthdr));
    MysqlPcap *mp = calloc(1, sizeof(*mp));

    if ((NULL == pcap_pkthdr) || (NULL == pkt_data) || (NULL == mp)) return ERR;

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
            default:
                printf("-%s", usage);
                return ERR;
        }
    }

    if (0 != single_process(argv[0])) return ERR; 

    sig_init();

    mp->pd = pcap_open_live(mp->netDev, CAPLEN, 0, 0, ebuf);

    if (NULL == mp->pd) {
        alog(L_ERROR, "pcap_open_live error: %s - %s\n", mp->netDev, ebuf);

        snprintf(mp->netDev, sizeof(mp->netDev), "%s", "bond0");
        mp->pd = pcap_open_live(mp->netDev, CAPLEN, 0, 0, ebuf);

        if (NULL == mp->pd) {
            alog(L_ERROR, "pcap_open_live error: %s - %s\n", "bond0", ebuf);
            printf("pcap_open_live error: %s - %s\n", "bond0", ebuf);
            return ERR;
        }
    }

    if (pcap_lookupnet(mp->netDev, &mp->localnet, &mp->netmask, ebuf) < 0) {
        alog(L_ERROR, "pcap_open_live error: %s - %s\n", mp->netDev, ebuf);
        printf("pcap_lookupnet error: %s", ebuf);
            return ERR;
    }

    alog(L_INFO, "Listen Device is %s", mp->netDev);

    if (ERR == set_filter(mp)) return ERR;

    for (;;) {
        if (1 == pcap_next_ex(mp->pd, &pcap_pkthdr, (const u_char **)&pkt_data)) {
            pkt_stat(mp, pcap_pkthdr, pkt_data);
        }
    }

    pcap_close(mp->pd);
    free(mp);
    free(pkt_data);
    free(pcap_pkthdr);

    alog(L_INFO, "why go here ?");
    return OK;
}


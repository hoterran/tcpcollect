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

#define	OK	(0)
#define	ERR	(-1)
#define	PEND	(1)

#define	SIZE_ETHERNET	14
#define ETHER_ADDR_LEN	6
#define HOSTNAME_LEN	128

#define	PKT_TYPE_TCP	1
#define	PKT_TYPE_UDP	2

#define	OUTPUT_INTERVAL	300

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
};

#define SLL_HDR_LEN     16              /* total header length */
#define SLL_ADDRLEN     8               /* length of address field */
        
struct sll_header {                                                                                                           
        u_int16_t       sll_pkttype;    /* packet type */
        u_int16_t       sll_hatype;     /* link-layer address type */
        u_int16_t       sll_halen;      /* link-layer address length */
        u_int8_t        sll_addr[SLL_ADDRLEN];  /* link-layer address */
        u_int16_t       sll_protocol;   /* protocol */
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

const struct sniff_ethernet *ethernet; /* The ethernet header */
const struct sniff_ip *iphdr; /* The IP header */
const struct sniff_tcp *tcphdr; /* The TCP header */
const char *payload; /* Packet payload */

u_int size_iphdr;
u_int size_tcphdr;

typedef struct statArgTag {
	uint8_t		pktType;
} StatArg;

#define	FILTER_STR_LEN	256
typedef struct servicePortTag{
	uint16_t	port;
	//char		filterStr[FILTER_STR_LEN];
	struct servicePortTag	*next;
} ServicePort;
typedef struct serviceIpTag{
	struct in_addr	addr;
	ServicePort	*portList;
	struct serviceIpTag	*next;
} ServiceIp;
typedef struct agentInfoTag {
	char		hostname[HOSTNAME_LEN];
	redisContext	*context;
	pcap_t		*pd;
	ServiceIp	*ipList;
	char		filter[10240];
	bpf_u_int32	netmask;
} AgentInfo;

#define	MAX_PORT_NUM	65536
#define	SIZE_IP	16
typedef struct portTrafficTag {
	uint16_t	port;
	size_t		inTraffic;
	size_t		inPkt;
	size_t		outTraffic;
	size_t		outPkt;
	time_t		old;
	time_t		now;
} PortTraffic;

typedef struct serviceTrafficTag {
	struct in_addr	addr;
	PortTraffic	portTraffic[MAX_PORT_NUM];
	struct serviceTrafficTag	*next;
} ServiceTraffic;


AgentInfo	Gagent;
ServiceTraffic	*Gtraffic = NULL;

uint8_t		GoutputFlg = 0;
char		GredisIp[SIZE_IP];
int		    GredisPort;
char		GredisPw[64];
char		Gdev[64];

ServiceTraffic *lookup_traffic (ServiceTraffic *list, struct in_addr addr);
void destory_iplist(AgentInfo *agent);
void destory_traffic_list(AgentInfo *agent);
int init_agent(AgentInfo *agent);

#define	L_ERROR	0
#define	L_WARN	1
#define	L_INFO	2

void
alog (int level, char *fmt, ...)
{
	char		levelStr[][32] = {"ERROR", "WARN", "INFO"};
	char		head[128], body[10240],logname[128];
	struct tm	tm;
	time_t		t;
	va_list		ap;
	FILE		*fp;
	
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
stat_traffic (uint8_t isIn, struct in_addr addr, uint16_t port, uint16_t bytes)
{
	ServiceTraffic	*now = Gtraffic;
	while (NULL != now) {
		if(addr.s_addr == now->addr.s_addr) {
			if (isIn) {
				now->portTraffic[port].inTraffic += bytes;
				now->portTraffic[port].inPkt++;
			} else {
				now->portTraffic[port].outTraffic += bytes;
				now->portTraffic[port].outPkt++;
			}
		}
		now = now->next;
	}
}

int
write_redo_log (const char *key, const char *val)
{
	FILE	*fp;

	fp = fopen ("/tmp/webdump-agent.redo", "a+");
	if (NULL == fp) {
		alog(L_ERROR, "can't open file /tmp/webdump-agent.redo");
		return ERR;
	}
	alog(L_INFO, "WRITE REDO LOG: %s,%s", key, val);
	fprintf(fp, "%s,%s\n", key, val);
	fclose(fp);
	return OK;
}

void
output_traffic()
{
	ServiceIp	*nowIp = NULL;
	ServicePort	*nowPort = NULL;
	ServiceTraffic	*nowTraffic = NULL;
	long		in, out, inPkt, outPkt;
	char		ip[SIZE_IP];
	char		key[256], val[256];
	struct tm	tm;
	time_t		t;
	redisReply	*reply;

	nowIp = Gagent.ipList;
	time(&t);
	localtime_r(&t, &tm);
	while (NULL != nowIp) {
		nowTraffic = lookup_traffic(Gtraffic, nowIp->addr);
		nowPort = nowIp->portList;
		while (NULL != nowPort) {
			in = nowTraffic->portTraffic[nowPort->port].inTraffic;
			out = nowTraffic->portTraffic[nowPort->port].outTraffic;
            inPkt = nowTraffic->portTraffic[nowPort->port].inPkt;
            outPkt = nowTraffic->portTraffic[nowPort->port].outPkt;

			/* clear old traffic*/
			nowTraffic->portTraffic[nowPort->port].inTraffic = 0;
			nowTraffic->portTraffic[nowPort->port].outTraffic = 0;
            nowTraffic->portTraffic[nowPort->port].inPkt = 0;
            nowTraffic->portTraffic[nowPort->port].outPkt = 0;

			inet_ntop(AF_INET, (void *)&(nowIp->addr), ip, SIZE_IP);
			//printf("%s:%d in:%lu out:%lu\n", ip, nowPort->port, in, out);
			snprintf(key, sizeof(key),  "traffic:%s:%s:%d",
				Gagent.hostname, ip, nowPort->port); 
			snprintf(val, sizeof(val), "%ld@%ld@%d-%d-%d %d:%d@%ld@%ld", 
				in, out, \
				1900+tm.tm_year, tm.tm_mon+1, tm.tm_mday, tm.tm_hour, tm.tm_min,
                inPkt, outPkt);
			alog(L_INFO, "key: %s, val: %s", key, val);
			if (NULL != Gagent.context) {
				reply = redisCommand(Gagent.context, "lpush %s %s", key, val);
			} else {
				goto writeredolog;
			}
			if (NULL == reply) {
				alog(L_ERROR, "redisCommand error.");
				goto writeredolog;
			} else {
				alog(L_INFO, "lpush reply %d: %s", reply->type, NULL == reply->str ? "NULL" : reply->str);
				freeReplyObject(reply);
			}
			nowPort = nowPort->next;
			continue;
writeredolog:		write_redo_log(key, val);
			nowPort = nowPort->next;
		}
		nowIp = nowIp->next;
	}
}
void pkt_stat (u_char *user, const struct pcap_pkthdr *h, const u_char *s)
{
	struct tm	*tm;
	time_t		timeStampSec; 
	char		src_ip[SIZE_IP], dst_ip[SIZE_IP];
	uint16_t	src_port, dst_port;
	StatArg		*statArg;

	statArg = (StatArg *)user;

	timeStampSec = h->ts.tv_sec;
	tm = localtime(&timeStampSec);

	//use any device, so not ethernet, but sll protocol
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
	/*
	printf("%d-%d-%d %d:%d:%d caplen:%d len:%d %s:%d->%s:%d ip_total_bytes:%d\n\n", 
		1900+tm->tm_year, 1+tm->tm_mon, tm->tm_mday, 
		tm->tm_hour, tm->tm_min, tm->tm_sec,
		h->caplen, h->len,
		src_ip, src_port, dst_ip, dst_port,
		ntohs(iphdr->ip_len));
	*/

	stat_traffic(1, iphdr->ip_dst, ntohs(tcphdr->th_dport), ntohs(iphdr->ip_len));
	stat_traffic(0, iphdr->ip_src, ntohs(tcphdr->th_sport), ntohs(iphdr->ip_len));

	return;
}

int
parse_ip_port (struct in_addr *addr, uint16_t *p, char *ipPort, int len)
{
	char	ip[16];
	char	port[6];
	uint8_t	is_port = 0;
	int	i, j, k;

	if (len > 21) return ERR;
	memset(ip, 0, sizeof(ip));
	memset(port, 0, sizeof(port));
	for (i=0, j=0, k=0; i < len; i++) {
		if (':' == ipPort[i]) {
			is_port = 1;
			continue;
		}
		
		if (is_port) {
			port[j++] = ipPort[i];
		} else {
			ip[k++] = ipPort[i];
		}
	}
	*p = atoi(port);
	inet_aton(ip, addr);
	return OK;
}

ServiceIp *
lookup_service (ServiceIp *list, struct in_addr addr)
{
	ServiceIp	*now, *prev;	
	now = list;
	while (NULL != now) {
		if (addr.s_addr == now->addr.s_addr)
			return (now);
		prev = now;
		now = now->next;
	}

	prev->next = calloc(1, sizeof(ServiceIp));
	if (NULL == prev->next) {
		alog(L_ERROR, "calloc error.");
		exit(ERR);
	}
	return (prev->next);
}

ServicePort *
lookup_port (ServicePort *list, uint16_t port)
{
	ServicePort	*now, *prev;

	now = list;
	while(NULL != now) {
		if (port == now->port)
			return (now);
		prev = now;
		now = now->next;
	}
	
	prev->next = calloc(1, sizeof(ServicePort));
	if (NULL == prev->next) {
		alog(L_ERROR, "calloc error.");
		exit(ERR);
	}
	return (prev->next);
}

int
add_port_list (ServicePort *list, uint16_t port) {
	ServicePort	*node;

	node = lookup_port(list, port);
	node->port = port;
	return OK;
}

int
add_service_list (struct in_addr addr, uint16_t port)
{
	ServiceIp	*node;

	if (NULL == Gagent.ipList) {
		Gagent.ipList = calloc(1, sizeof(ServiceIp));
		if (NULL == Gagent.ipList){
			alog(L_ERROR, "calloc error.");
			exit(ERR);
		}
		Gagent.ipList->addr = addr;
		if (NULL == (Gagent.ipList->portList = calloc(1, sizeof(ServicePort)))) {
			alog(L_ERROR, "calloc error.");
			exit(ERR);
		}
		Gagent.ipList->portList->port = port;
		return OK;
	}

	node = lookup_service(Gagent.ipList, addr);
	node->addr = addr;
	if (NULL == node->portList) {
		if (NULL == (node->portList = calloc(1, sizeof(ServicePort)))) {
			alog(L_ERROR, "calloc error.");
			exit(ERR);
		}
		node->portList->port = port;
		return OK;
	}
	add_port_list(node->portList, port);

	return OK;
}

ServiceTraffic *
lookup_traffic (ServiceTraffic *list, struct in_addr addr)
{
	ServiceTraffic	*now, *prev;

	now = list;
	while (NULL != now) {
		if (addr.s_addr == now->addr.s_addr)
			return (now);
		prev = now;
		now = now->next;
	}
	prev->next = calloc(1, sizeof(ServiceTraffic));
	if (NULL == prev->next) {
		alog(L_ERROR, "calloc error.");
		exit(ERR);
	}
	prev->next->addr.s_addr = addr.s_addr;

	return (prev->next);
}

int
add_traffic_list (struct in_addr addr)
{
	if (NULL == Gtraffic) {
		Gtraffic = calloc(1, sizeof(ServiceTraffic));
		if (NULL == Gtraffic) {
			alog(L_ERROR, "calloc error.");
			exit(ERR);
		}
		Gtraffic->addr = addr;
		return OK;
	}
	lookup_traffic(Gtraffic, addr);

	return OK;
}

void
destory_traffic_list (AgentInfo *agent)
{
	ServiceTraffic	*now, *tmp;

	if (NULL == agent->context) {
		alog(L_WARN, "redis handle is NULL.");
		return;
	}
	now = Gtraffic;
	while(NULL != now) {
		tmp = now;
		now = now->next;
		free(tmp);
	}
	Gtraffic = NULL;
}

int
init_service_list (AgentInfo *agent)
{
	redisReply	*reply;
	int		i;
	struct in_addr	addr;
	uint16_t	port;
	redisContext	*c = agent->context;

	gethostname(agent->hostname, sizeof(agent->hostname));
	alog(L_INFO, "now get local hostname: %s", agent->hostname);
	//snprintf(agent->hostname, sizeof(agent->hostname), "lvstest2b");

	if(NULL == agent->context) {
		alog(L_WARN, "not connect redis server.");
		return OK;
	}
	reply = redisCommand(c, "hgetall hostname:%s", agent->hostname);
	if (REDIS_REPLY_ARRAY != reply->type) {
		alog(L_WARN, "get host config error.");
		freeReplyObject(reply);
		return ERR;
	}
	if (0 == reply->elements) {
		alog(L_WARN, "hgetall hostname:%s is null", agent->hostname);
		freeReplyObject(reply);
		return ERR;
	}

	destory_iplist(agent);
	destory_traffic_list(agent);
	memset(agent->filter, 0, sizeof(agent->filter));

	for (i = 0; i < reply->elements; i++) {
		if ( 0 == i % 2) {
			parse_ip_port(&addr, &port, reply->element[i]->str, reply->element[i]->len);
			char	ip[16];
			add_service_list(addr, port);
			add_traffic_list(addr);
			inet_ntop(AF_INET, (void *)&addr, ip, SIZE_IP);
			alog(L_INFO, "ip: %s, port: %d", ip, port);
		} else {
			alog(L_INFO, "single filter: %s", reply->element[i]->str);
			if (strlen(agent->filter) + reply->element[i]->len < sizeof(agent->filter)) {
				snprintf(agent->filter + strlen(agent->filter), sizeof(agent->filter), 
					"%s(%s)", 1 == i ? "" : " or ", reply->element[i]->str);
			}
		}
	}
	freeReplyObject(reply);

	/* get global filter */
	reply = redisCommand(c, "get global:hostname:%s", agent->hostname);
	if (REDIS_REPLY_STRING == reply->type) {
		if (strlen(agent->filter) + reply->len < sizeof(agent->filter)) {
			snprintf(agent->filter + strlen(agent->filter), 
				sizeof(agent->filter), " and (%s)", reply->str);
		} else {
			alog(L_WARN, "filter len is error %s", agent->filter);
			exit(1);		
		}
	} else {
		alog(L_WARN, "not add global filter.");
	}

	alog(L_INFO, "total filter: %s", agent->filter);
	freeReplyObject(reply);
	return OK;
}

int
init_agent (AgentInfo *agent)
{
	struct bpf_program      fcode;
	struct timeval		timeout = {3, 0};
	int	i;
	redisReply		*reply;

	if (agent->context) {
		redisFree(agent->context);
		agent->context = NULL;
	}

	for (i = 0; i < 3; i++) {
		agent->context = redisConnectWithTimeout(GredisIp, GredisPort, timeout);
		if (agent->context->err) {
			alog(L_WARN, "connect redis server %s:%d failed: %s", 
				GredisIp, GredisPort, agent->context->errstr);
			redisFree(agent->context);
			agent->context = NULL;
			continue;
		}
		break;
	}
	if (NULL == agent->context) {
		alog(L_ERROR, "can't connect redis server %s:%d", GredisIp, GredisPort); 
		alog(L_WARN, "keep old config");
		return PEND;
	}

	reply = redisCommand(agent->context, "auth %s", GredisPw);
	if (0 != strcmp(reply->str, "OK")) {
		alog(L_ERROR, "invalid redis passwd: %s", GredisPw);
		printf("invalid redis passwd: %s\n", GredisPw);
		freeReplyObject(reply);
		return PEND;
	}
	freeReplyObject(reply);

	if (ERR == init_service_list(agent)) {
		alog(L_ERROR, "init_service_list error.");
		redisFree(agent->context);
		agent->context = NULL;
		return ERR;
	}

        if (pcap_compile(agent->pd, &fcode, agent->filter, 0, agent->netmask) < 0) {
                alog(L_WARN, "pcap_compile failed: %s", pcap_geterr(agent->pd));
		pcap_freecode(&fcode);
                return ERR;
        }

        if (pcap_setfilter(agent->pd, &fcode) < 0) {
                alog(L_WARN, "pcap_setfilter failed: %s", pcap_geterr(agent->pd));
		pcap_freecode(&fcode);
                return ERR;
        }

	pcap_freecode(&fcode);
	return OK;
}

void
destory_iplist (AgentInfo *agent)
{
	ServiceIp	*nowIp, *tmpIp;
	ServicePort	*nowPort, *tmpPort;

	if (NULL == agent->context) {
		alog(L_WARN, "redis handle is NULL.");
		return;
	}
	nowIp = agent->ipList;
	while (NULL != nowIp) {
		tmpIp = nowIp;
		nowPort = nowIp->portList;
		while (NULL != nowPort) {
			tmpPort = nowPort;
			nowPort = nowPort->next;
			free(tmpPort);
		}
		nowIp = nowIp->next;
		free(tmpIp);
	}
	agent->ipList = NULL;
}
void
switch_flg(int sig)
{
	if (SIGALRM == sig) GoutputFlg = 1;
}

int daemon_init(void)
{
        pid_t pid;
        if((pid = fork())< 0)
        {
                return ERR;
        }
        else if(pid > 0)                
        {
                alog(L_INFO, "parent process exit.");
                exit(0);
        }

        setsid();                         
        if((pid = fork()) < 0)
        {
                return ERR;
        }
        else if(pid > 0)                 
        {
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
        /*
         *      lock file /var/lock/PROCESS_NAME.pid
         *
         */
        char lockfile[128];
        
        snprintf(lockfile, sizeof(lockfile), "/var/lock/%s.pid", basename(process_name));
        
        lock_fd = open(lockfile, O_CREAT|O_WRONLY, 00200);
        
        if (lock_fd <= 0) {
                printf("Cant fopen file %s for %s\n", lockfile, strerror(errno)); 
                return -1;
        }                                                                                                                     
        //F_LOCK will hang until unlock, F_TLOCK will return asap
        int ret = lockf(lock_fd, F_TLOCK, 0);
        
        if (ret == 0) {
                return 0;
        } else {
                printf("Cant lock %s for %s\n", lockfile, strerror(errno));
                return -1;
        }
}

void sig_init(void)
{
	/*
		block some sig
		SIGTERM
		SIGHUP
		SIGPIPE
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

int
main (int argc, char **argv)
{
	char			ebuf[PCAP_ERRBUF_SIZE];
	pcap_t			*pd = NULL;
	bpf_u_int32		localnet, netmask;
	StatArg			statArg;
	u_char			*pcapUserData;
	char			ch;
	char			usage[] = "Usage:\n\twebdump-agent -h [redis server ip] -p [redis server port] -P [passwd] -d [dev]\n";
	struct pcap_pkthdr	*pcap_pkthdr;
	u_char			*pkt_data;

	daemon_init();

	statArg.pktType = PKT_TYPE_TCP;
	pcapUserData = (u_char *)&statArg;

	signal(SIGALRM, switch_flg);

	if (0 != single_process(argv[0]))
		return -1;

	sig_init();

	memset(&Gagent, 0, sizeof(Gagent));

    while (-1 != (ch = getopt(argc, argv, "p:h:P:d:"))) {
        switch (ch) {
            case 'p' :
                GredisPort = atoi(optarg);
                break;
            case 'h' :
                snprintf(GredisIp, sizeof(GredisIp), "%s", optarg);
                break;
            case 'P' :
                snprintf(GredisPw, sizeof(GredisPw), "%s", optarg);
                break;
            case 'd' :
                snprintf(Gdev, sizeof(Gdev), "%s", optarg);
                break;
            default:
                printf("-%s", usage);
                return ERR;
        }
    }

	int i;
	for (i = 1; i < argc; i++) {
		memset(argv[i], 0, strlen(argv[i]));
	}
	/*
	device = pcap_lookupdev(ebuf);
	if (NULL == device) {
		printf("lookupdev error: %s\n", ebuf);
	} else {
		alog(L_INFO, "capture on device: %s\n", device);
	}
	*/
    if (strlen(Gdev) == 0)
        snprintf(Gdev, sizeof(Gdev), "%s", "bond0");

	pd = pcap_open_live(Gdev, 68, 0, 1000, ebuf);
	if (NULL == pd) {
		alog(L_ERROR, "pcap_open_live error: %s - %s\n", Gdev, ebuf);
		//return ERR;
        snprintf(Gdev, sizeof(Gdev), "%s", "eth0");
		pd = pcap_open_live(Gdev, 68, 0, 1000, ebuf);
		if (NULL == pd) {
            alog(L_ERROR, "pcap_open_live error: %s - %s\n", Gdev, ebuf);
			printf("pcap_open_live error: %s - %s\n", Gdev, ebuf);
			return ERR;
		}
	}
	Gagent.pd = pd;
	if (pcap_lookupnet(Gdev, &localnet, &netmask, ebuf) < 0) {
        alog(L_ERROR, "pcap_open_live error: %s - %s\n", Gdev, ebuf);
		printf("pcap_lookupnet error: %s", ebuf);
		return ERR;
	}

    alog(L_INFO, "Listen device is %s", Gdev);

	Gagent.netmask = netmask;

	while(1) {
	/* first time, must get config from redis */
		if (OK != init_agent(&Gagent)) {
			alog(L_ERROR, "init_agent error, retry after 30 seconds.");
			sleep(30);
		} else {
			break;
		}
	}

	pcap_pkthdr = calloc(1, sizeof(struct pcap_pkthdr));
	pkt_data = calloc(1500, sizeof(u_char));
	/* set alarm */
	alarm(OUTPUT_INTERVAL);
	for (;;) {
		if (1 == pcap_next_ex(pd, &pcap_pkthdr, (const u_char **)&pkt_data)) {
			pkt_stat(pcapUserData, pcap_pkthdr, pkt_data);
		}

		if (GoutputFlg) {
			alog(L_INFO, "output traffic.");
			GoutputFlg = 0;
			output_traffic();
			init_agent(&Gagent);
			/* reset alarm */
			alarm(OUTPUT_INTERVAL);
		}

	}

	pcap_close(pd);
	return OK;
}


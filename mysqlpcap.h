#ifndef _MYSQLPCAP_
#define _MYSQLPCAP_


#define OK      (0)
#define ERR     (-1)
#define PEND    (1)

#define CAP_LEN 65536

typedef struct _MysqlPcap {
    pcap_t      *pd;
    int         mysqlPort;
    char        filter[10240];
    char        netDev[10];
    bpf_u_int32 netmask;
    bpf_u_int32 localnet;
    char        logfile[256];
    char        keyWord[256];
    void*       al;
    void*       hash;
} MysqlPcap;

#endif

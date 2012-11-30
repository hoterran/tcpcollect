#ifndef _MYSQLPCAP_
#define _MYSQLPCAP_

#include <pcap.h>

typedef struct _MysqlPcap {
    void        *pd;
    int         mysqlPort;
    char        filter[10240]; /* 15(ip) * 100 */
    char        netDev[10];
    bpf_u_int32 netmask;
    bpf_u_int32 localnet;
    char        logfile[256];
    char        keyWord[256];
    void        *al;
    void        *hash;
    char        *address;
    int         isShowSrcIp;
    void        *focusUser;
    void        *filterUser;
} MysqlPcap;

#endif

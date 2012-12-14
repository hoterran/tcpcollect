#ifndef _MYSQLPCAP_
#define _MYSQLPCAP_

#include <pcap.h>
#include <sys/time.h>

typedef struct _MysqlPcap {
    void        *pd;
    int         mysqlPort;
    char        filter[10240]; /* 15(ip) * 100 */
    char        netDev[10];
    bpf_u_int32 netmask;
    bpf_u_int32 localnet;
    char        logfile[256];
    FILE        *dataLog;
    void        *dataLogCache;
    char        keyWord[256];
    void        *al;
    void        *hash;
    char        *address;
    int         isShowSrcIp;
    void        *focusUser;
    void        *filterUser;
    time_t      fakeNow;
    time_t      lastReloadAddressTime;
    time_t      lastFlushTime;
} MysqlPcap;

#endif

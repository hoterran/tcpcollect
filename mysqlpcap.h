#ifndef _MYSQLPCAP_
#define _MYSQLPCAP_


#define OK      (0)
#define ERR     (-1)
#define PEND    (1)

typedef unsigned short uint16;
typedef unsigned int uint;
typedef unsigned int uint32;
typedef unsigned char uchar;
typedef unsigned long ulong;

#define CAP_LEN 65536

#include <pcap.h>

typedef struct _MysqlPcap {
    void        *pd;
    int         mysqlPort;
    char        filter[10240];
    char        netDev[10];
    bpf_u_int32 netmask;
    bpf_u_int32 localnet;
    char        logfile[256];
    char        keyWord[256];
    void*       al;
    void*       hash;
    char*       address;
    int         isShowSrcIp;
} MysqlPcap;

#endif

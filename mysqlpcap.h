#ifndef _MYSQLPCAP_
#define _MYSQLPCAP_

struct _MysqlPcap;
typedef struct _MysqlPcap MysqlPcap;

typedef int (*initFp) (MysqlPcap *);
typedef int (*addFp) (MysqlPcap *, const char *fmt, ...);
typedef int (*flushFp) (MysqlPcap *, int force);

#include <pcap.h>
#include <sys/time.h>

#define HOST_NAME_LEN 64

struct _MysqlPcap {
    void        *pd;
    char        hostname[HOST_NAME_LEN];
    int         mysqlPort;
    char        filter[10240]; /* 15(ip) * 100 */
    char        netDev[10];
    bpf_u_int32 netmask;
    bpf_u_int32 localnet;
    char        keyWord[256];
    void        *hash;

    pthread_mutex_t aux_mutex;
    pthread_t       aux_thread_id;
    char        *address;           /* user input */
    void        *al;                /* address list */
    void        *new_al;            /* new list, lock then switch*/

    int         isShowSrcIp;
    void        *focusUser;
    void        *filterUser;
    time_t      fakeNow;
    time_t      lastReloadAddressTime;
    long        packetSeq;          /* packet sequence */
    /* for debug */
    ulong       datalen;
    char        is_in;
    uint32    tcp_seq;

    /* cache */
    initFp      initCache;
    addFp       addCache;
    flushFp     flushCache;

    char        cacheFileName[256]; /* only use file cache */
    char        cacheConfigFileName[256]; /* redis config, mysql config */

    void        *config;      /* fd, redisContext, MYSQL */
    time_t      cacheFlushTime;
};

#endif

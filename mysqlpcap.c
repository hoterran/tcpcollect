#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <time.h>

#include "utils.h"
#include "log.h"
#include "mysqlpcap.h"
#include "packet.h"
#include "address.h"
#include "hash.h"
#include "adlist.h"
#include "user.h"

void init(MysqlPcap *mp) {

    if (NULL == mp->dataLog) mp->dataLog = stdout;
    mp->dataLogCache = malloc(100 * 1024);
    setbuffer(mp->dataLog, mp->dataLogCache, 100 * 1024);

    if (mp->mysqlPort == 0) 
        mp->mysqlPort = 3306;
    if (strlen(mp->netDev) == 0)
        snprintf(mp->netDev, sizeof(mp->netDev), "%s", "any");
    if (mp->address) {
        dump(L_WARN, "address %s", mp->address);
        mp->al = parse_addresses(mp->address);
    } else {
        mp->al = get_addresses();
    }
    mp->lastReloadAddressTime = time(NULL);
    mp->fakeNow = mp->lastReloadAddressTime;
    mp->lastFlushTime = mp->lastReloadAddressTime;
    mp->hash = hash_new();
}

int main (int argc, char **argv) {

    log_init("mysqlpcap", NULL, ".log", L_DEBUG);

    char usage[] = "Usage: \n\tmysqlpcap -p [port] mysql listen port default 3306\n"
                    "\t -d daemon default no\n "
                    "\t -f [filename] default stdout \n"
                    "\t -i [dev] \n"
                    "\t -l address1,address2 \n"
                    "\t -z show source ip\n"
                    "\t -u focus user, sperated by comma, default null, example: user1,user2, conflict with -n \n"
                    "\t -n filter user, format same as above but conflict with -u\n"
                    "\t -h help";

    MysqlPcap *mp = calloc(1, sizeof(*mp));

    if (NULL == mp) return ERR;

    char ch;
    while (-1 != (ch = getopt(argc, argv, "p:df:k:i:l:hz:u:n:"))) {
        switch (ch) {
            case 'p' :
                mp->mysqlPort = atoi(optarg);
                break;
            case 'd' :
                daemon_init();
                break;
            case 'f':
                snprintf(mp->logfile, sizeof(mp->logfile), "%s", optarg);
                mp->dataLog = fopen(mp->logfile, "a+");
                if (NULL == mp->dataLog) {
                    dump(L_ERR, "%s can open", mp->logfile); 
                }
                break;
            case 'k' :
                snprintf(mp->keyWord, sizeof(mp->keyWord), "%s", optarg); 
                break;
            case 'i' :
                snprintf(mp->netDev, sizeof(mp->netDev), "%s", optarg); 
                break; 
            case 'u' :
                if (mp->filterUser) {
                    printf("-u conflict with -n\n"); 
                    return ERR;
                }
                mp->focusUser = listCreate();
                initUserList(mp->focusUser, optarg);
                break; 
            case 'n' :
                if (mp->focusUser) {
                    printf("-n conflict with -u\n"); 
                    return ERR;
                }
                mp->filterUser = listCreate();
                initUserList(mp->filterUser, optarg);
                break; 
            case 'l':
                mp->address = malloc(strlen(optarg) + 1);
                snprintf(mp->address, strlen(optarg) + 1, "%s", optarg);
                break;
            case 'z':
                mp->isShowSrcIp = 1;
                break;
            case 'h' :
            default :
                printf("%s", usage);
                return ERR;
        }
    }

    init(mp);

    if (0 != single_process(argv[0])) {
        dump(L_ERR, "only single process");
        return ERR; 
    }

    sig_init();

    start_packet(mp);

    hash_free(mp->hash);
    free(mp->hash);
    free(mp);

    dump(L_ERR, "exit0");
    return OK;
}


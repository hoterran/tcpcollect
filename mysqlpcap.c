#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <time.h>
#include <libgen.h>
#include <pthread.h>

#include "utils.h"
#include "log.h"
#include "protocol.h"
#include "mysqlpcap.h"
#include "packet.h"
#include "address.h"
#include "hash.h"
#include "adlist.h"
#include "user.h"
#include "file_cache.h"

/* two primer */
#define AUX_THREAD_SLEEP_TIME 33 * 61
 
void *aux_thread(void *arg) {
    MysqlPcap *mp = arg;
    while(1) {
        pthread_mutex_lock(&mp->aux_mutex);
        if (mp->new_al) {
            free_addresses(mp->new_al);
        }
        mp->new_al = get_addresses();
        pthread_mutex_unlock(&mp->aux_mutex);
        select_sleep(AUX_THREAD_SLEEP_TIME);
        dump(L_WARN, "thread reload address");
    }
}

int init(MysqlPcap *mp) {
    ASSERT(mp);
    /* file_cache */
    mp->initCache = fileCacheInit;
    mp->addCache = fileCacheAdd;
    mp->flushCache = fileCacheFlush;

    gethostname(mp->hostname, sizeof(mp->hostname));

    if (ERR == mp->initCache(mp)) return ERR;

    if (mp->mysqlPort == 0) 
        mp->mysqlPort = 3306;
    if (strlen(mp->netDev) == 0)
        snprintf(mp->netDev, sizeof(mp->netDev), "%s", "any");
    if (mp->address) {
        dump(L_WARN, "address %s", mp->address);
        mp->al = parse_addresses(mp->address);
    } else {
        pthread_mutex_init(&mp->aux_mutex, NULL);
        mp->al = get_addresses();
        pthread_create(&mp->aux_thread_id, NULL, aux_thread, mp); 
    }
    mp->lastReloadAddressTime = time(NULL);
    mp->fakeNow = mp->lastReloadAddressTime;
    mp->hash = hash_new();
    return OK;
}

int main (int argc, char **argv) {

    char *s = strdup(argv[0]);
    chdir(dirname(s));
    free(s);

    log_init("mysqlpcap", NULL, ".log", L_OK);

    char usage[] = "Usage: \n\tmysqlpcap -p [port] mysql listen port default 3306\n"
                    "\t -d daemon default no\n "
                    "\t -f [filename] default stdout \n"
                    "\t -c config file \n"
                    "\t -i [dev] \n"
                    "\t -l address1,address2 \n"
                    "\t -z show source ip\n"
                    "\t -u focus user, sperated by comma, default null, example: user1,user2, conflict with -n \n"
                    "\t -n filter user, format same as above but conflict with -u\n"
                    "\t -h help";

    MysqlPcap *mp = calloc(1, sizeof(*mp));

    if (NULL == mp) return ERR;

    char ch;
    while (-1 != (ch = getopt(argc, argv, "p:df:c:k:i:l:hzu:n:"))) {
        switch (ch) {
            case 'p' :
                mp->mysqlPort = atoi(optarg);
                break;
            case 'd' :
                daemon_init();
                break;
            case 'f':
                /* cache write this file, conflict with -c */
                snprintf(mp->cacheFileName, sizeof(mp->cacheFileName), "%s", optarg);
                break;
            case 'c':
                /* cache config file, conflict with -f */
                snprintf(mp->cacheConfigFileName, sizeof(mp->cacheConfigFileName), "%s", optarg);
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
            case 'z':
                mp->isShowSrcIp = 1;
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
            case 'h' :
            default :
                printf("%s", usage);
                return ERR;
        }
    }

    if (ERR == init(mp)) {
        return ERR; 
    }

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


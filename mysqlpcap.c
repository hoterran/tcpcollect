#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>

#include "utils.h"
#include "log.h"
#include "mysqlpcap.h"
#include "packet.h"
#include "address.h"
#include "hash.h"

void init(MysqlPcap *mp) {
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
    mp->hash = hash_new();
}

int main (int argc, char **argv) {

    log_init("mysqlpcap", NULL, ".log");

    char usage[] = "Usage: \n\tmysqlpcap -p [port] mysql listen port default 3306\n"
                    "\t -d daemon default no\n "
                    "\t -f [filename] default tty\n"
                    "\t -i [dev] (eth* card use this)\n"
                    "\t -l address1,address2 (bond card or use this)\n"
                    "\t -z show source ip\n"
                    "\t -h help";

    MysqlPcap *mp = calloc(1, sizeof(*mp));

    if (NULL == mp) return ERR;

    char ch;
    while (-1 != (ch = getopt(argc, argv, "p:df:k:i:l:hz"))) {
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


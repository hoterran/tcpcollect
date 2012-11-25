#ifndef PACKET_H
#define PROCESS_PACKET_H

#include <netinet/ip.h>
#include <pcap.h>

#include "mysqlpcap.h"

#define CAP_LEN 65536

int start_packet(MysqlPcap * mp);


#endif

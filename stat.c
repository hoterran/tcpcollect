#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "utils.h"
#include "log.h"

/* save last packet information for debug */
#define LAST_PACKETS_NUM 20

/* TODO save first ten bytes */
typedef struct _Packet {
    char incoming;
    uint32 datalen;
    uint32 tcp_seq;
    uint16 dport;
    uint16 sport;
} Packet;

Packet G_packet[LAST_PACKETS_NUM];
int G_pos;

void addPacketInfo(char incoming, uint32 datalen, uint32 tcp_seq,
    uint16 dport, uint16 sport) {
    ASSERT(G_pos <= LAST_PACKETS_NUM);
    ASSERT((incoming == '1') || (incoming == '0'));
    ASSERT((datalen > 0) && (dport > 0) && (sport > 0));

    if (G_pos == LAST_PACKETS_NUM) {
        G_pos = 0;
    }
    G_packet[G_pos].incoming = incoming;
    G_packet[G_pos].datalen = datalen;
    G_packet[G_pos].tcp_seq = tcp_seq;
    G_packet[G_pos].dport = dport;
    G_packet[G_pos].sport = sport;
    G_pos++;

    return;
}

/**/
void printPacketInfo() {
    /* 
     * ---------|------- 
     * <---1----- <---2--
    */
    int i = G_pos - 1;
    while(i >= 0) {
        dump(L_OK, "datalen:%u seq:%u dport:%u sport:%u incoming:%c",
            G_packet[i].datalen,
            G_packet[i].tcp_seq,
            G_packet[i].dport,
            G_packet[i].sport,
            G_packet[i].incoming);
        i--;
    }

    for (i = LAST_PACKETS_NUM - 1; i > G_pos - 1 ; i--) {
        dump(L_OK, "datalen:%u seq:%u dport:%u sport:%u incoming:%c",
            G_packet[i].datalen,
            G_packet[i].tcp_seq,
            G_packet[i].dport,
            G_packet[i].sport,
            G_packet[i].incoming);
    }
}


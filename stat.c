#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "utils.h"
#include "log.h"

/* save last packet information for debug */
#define LAST_PACKETS_NUM 40
#define PAYLOAD_SNAPSHOT_LEN 30

/* TODO save first ten bytes */
typedef struct _Packet {
    char incoming;
    uint32 datalen;
    uint32 tcp_seq;
    uint16 dport;
    uint16 sport;
    char payload[PAYLOAD_SNAPSHOT_LEN];
} Packet;

Packet G_packet[LAST_PACKETS_NUM];
int G_pos;

void addPacketInfo(char incoming, uint32 datalen, uint32 tcp_seq,
    uint16 dport, uint16 sport, char* payload) {
    ASSERT(G_pos <= LAST_PACKETS_NUM);
    ASSERT((incoming == '1') || (incoming == '0'));
    ASSERT((datalen >= 0) && (dport > 0) && (sport > 0));

    if (G_pos == LAST_PACKETS_NUM) {
        G_pos = 0;
    }
    G_packet[G_pos].incoming = incoming;
    G_packet[G_pos].datalen = datalen;
    G_packet[G_pos].tcp_seq = tcp_seq;
    G_packet[G_pos].dport = dport;
    G_packet[G_pos].sport = sport;

    int len = PAYLOAD_SNAPSHOT_LEN;
    if (datalen < PAYLOAD_SNAPSHOT_LEN) {
        len = datalen;
    }
   
    memset(G_packet[G_pos].payload, 0, len);
    memcpy(G_packet[G_pos].payload, payload, len);
    G_pos++;

    return;
}

/* byte array -> printable string array */
void printPacketArray(char *dst, uchar *src) {
    int i;
    for(i = 0; i < PAYLOAD_SNAPSHOT_LEN; i++) {
        snprintf(dst + strlen(dst), 5, "%x ", src[i]);
    }
}
/* print Last 10(count) packet */
void printLastPacketInfo(int count) {
    ASSERT(count >= 0);

   /* 
     * ---------|------- 
     * <---1----- <---2--
    */
    int i = G_pos - 1;
    char buffer[PAYLOAD_SNAPSHOT_LEN * 5 + 1];

    while(i >= 0) {
        memset(buffer, 0, PAYLOAD_SNAPSHOT_LEN + 5 + 1);
        printPacketArray(buffer, (uchar*)G_packet[i].payload);
        dump(L_OK, "datalen:%u seq:%u dport:%u sport:%u incoming:%c packet:\n\n%s\n",
            G_packet[i].datalen,
            G_packet[i].tcp_seq,
            G_packet[i].dport,
            G_packet[i].sport,
            G_packet[i].incoming, 
            buffer);
        i--;
        count--;
        if (count == 0) {
            return; 
        }
    }

    for (i = LAST_PACKETS_NUM - 1; i > G_pos - 1 ; i--, count--) {
        if (count == 0) {
            return; 
        }
        memset(buffer, 0, PAYLOAD_SNAPSHOT_LEN + 4 + 1);
        printPacketArray(buffer, (uchar*)G_packet[i].payload);
        dump(L_OK, "datalen:%u seq:%u dport:%u sport:%u incoming:%c\npacket:\n%s\n",
            G_packet[i].datalen,
            G_packet[i].tcp_seq,
            G_packet[i].dport,
            G_packet[i].sport,
            G_packet[i].incoming, 
            buffer);
    }
}

void printPacketInfo() {
    printLastPacketInfo(LAST_PACKETS_NUM);
}

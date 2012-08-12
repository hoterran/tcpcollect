/**
 *   tcprstat -- Extract stats about TCP response times
 *   Copyright (C) 2010  Ignacio Nin
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
**/

#include "process-packet.h"

#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#include <string.h>

#include <pcap.h>
#include <pcap/sll.h>

#include "log.h"
#include "local-addresses.h"
#include "mysqlpcap.h"

/*
    if dev has set, use it, else use 'any'
    if dev not exists use 'any'

*/

int
start_packet(MysqlPcap *mp) {

    struct bpf_program fcode;
    char filter[256];
    char ebuf[PCAP_ERRBUF_SIZE];

    mp->pd = pcap_open_live(mp->netDev, CAP_LEN, 0, 0, ebuf);
              
    if (NULL == mp->pd) {
        alog(L_WARN, "pcap_open_live error: %s - %s\n", mp->netDev, ebuf);
              
        snprintf(mp->netDev, sizeof(mp->netDev), "%s", "any");
        mp->pd = pcap_open_live(mp->netDev, CAP_LEN, 0, 0, ebuf);
              
        if (NULL == mp->pd) {
            alog(L_ERROR, "pcap_open_live error: %s - %s\n", "any", ebuf);
            printf("pcap_open_live error: %s - %s\n", "any", ebuf);
            return ERR;
        }
    }
              
    if (pcap_lookupnet(mp->netDev, &mp->localnet, &mp->netmask, ebuf) < 0) {
        alog(L_ERROR, "pcap_open_live error: %s - %s\n", mp->netDev, ebuf);
        return ERR;
    }         
              
    alog(L_OK, "Listen Device is %s", mp->netDev);

    //snprintf(filter, sizeof(filter), "tcp port %d ", mp->mysqlPort);

    snprintf(filter, sizeof(filter), 
        "tcp port %d and tcp[tcpflags] & (tcp-push) != 0", mp->mysqlPort);

    if (pcap_compile(mp->pd, &fcode, filter, 0, mp->netmask) < 0) {
        alog(L_WARN, "pcap_compile failed: %s", pcap_geterr(mp->pd));
        pcap_freecode(&fcode);
        return ERR;
    }

    if (pcap_setfilter(mp->pd, &fcode) < 0) {
        alog(L_WARN, "pcap_setfilter failed: %s", pcap_geterr(mp->pd));
        pcap_freecode(&fcode);
        return ERR;
    }

    pcap_freecode(&fcode);

    pcap_loop(mp->pd, -1, process_packet, (u_char *)mp);

    alog(L_ERROR, "pcap_open_live error: %s - %s\n", mp->netDev, ebuf);
              
    pcap_close(mp->pd);
}

void
process_packet(unsigned char *user, const struct pcap_pkthdr *header,
        const unsigned char *packet) {

    MysqlPcap *mp = (MysqlPcap *) user;

    const struct sll_header *sll;
    const struct ether_header *ether_header;
    const struct ip *ip;
    unsigned short packet_type;

    // Parse packet
    switch (pcap_datalink(mp->pd)) {
        
    case DLT_LINUX_SLL:
        sll = (struct sll_header *) packet;
        packet_type = ntohs(sll->sll_protocol);
        ip = (const struct ip *) (packet + sizeof(struct sll_header));
        
        break;
        
    case DLT_EN10MB:
        ether_header = (struct ether_header *) packet;
        packet_type = ntohs(ether_header->ether_type);
        ip = (const struct ip *) (packet + sizeof(struct ether_header));
        
        break;
        
    case DLT_RAW:
        packet_type = ETHERTYPE_IP; //This is raw ip
        ip = (const struct ip *) packet;
        
        break;
        
    default:
        
        return;
        
    }
    
    if (packet_type != ETHERTYPE_IP)
        return;
    
    process_ip(mp, ip, header->ts);
    
}

int
process_ip(MysqlPcap *mp, const struct ip *ip, struct timeval tv) {
    char src[16], dst[16], *addr;
    int incoming;
    unsigned len;
    
    addr = inet_ntoa(ip->ip_src);
    strncpy(src, addr, 15);
    src[15] = '\0';
    
    addr = inet_ntoa(ip->ip_dst);
    strncpy(dst, addr, 15);
    dst[15] = '\0';
    
    if (is_local_address(mp->al, ip->ip_src))
        incoming = 0;
    else if (is_local_address(mp->al, ip->ip_dst))
        incoming = 1;
    else
        return 1;
    
    len = htons(ip->ip_len);
    
    switch (ip->ip_p) {
        struct tcphdr *tcp;
        uint16_t sport, dport, lport, rport;
        unsigned datalen;
    
    case IPPROTO_TCP:
        tcp = (struct tcphdr *) ((unsigned char *) ip + sizeof(struct ip));
        
#if defined(__FAVOR_BSD)
        sport = ntohs(tcp->th_sport);
        dport = ntohs(tcp->th_dport);
        datalen = len - sizeof(struct ip) - tcp->th_off * 4;    // 4 bits offset 
#else
        sport = ntohs(tcp->source);
        dport = ntohs(tcp->dest);
        datalen = len - sizeof(struct ip) - tcp->doff * 4;
#endif

        // Capture only "data" packets, ignore TCP control
        if (datalen == 0)
            break;

        if (ip->ip_dst.s_addr == ip->ip_src.s_addr) { 
            if (dport == mp->mysqlPort) {
                incoming = 1; 
            } else 
                incoming = 0;
        }

        if (incoming) {
            lport = dport;
            rport = sport;
          
            char *data = (char*) ((unsigned char *) tcp + tcp->doff * 4);

            
            char *sql;
            int cmd = parse_sql(data, &sql, datalen);
            if (cmd >= 0)
                hash_set(mp->hash, ip->ip_dst, ip->ip_src, lport, rport, tv, sql, cmd);
            
        }
        else {
            lport = sport;
            rport = dport;

            struct timeval tv2;
            char *sql;
            if (1 == hash_get(mp->hash, ip->ip_src, ip->ip_dst, lport, rport, &tv2, &sql))
                printf("[%s] latency is %ldus\n", sql, (tv.tv_sec - tv2.tv_sec) * 1000000 + (tv.tv_usec - tv2.tv_usec));
        }

        break;
        
    default:
        break;
        
    }
    
    return 0;
    
}



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

#include <stdio.h>
#include <string.h>

#include <pcap.h>
#include <pcap/sll.h>
#include <time.h>
#include <assert.h>

#include "log.h"
#include "local-addresses.h"
#include "mysqlpcap.h"
#include "mysql-protocol.h"
#include "stats-hash.h"

#define likely(x)   __builtin_expect(!!(x), 1) 
#define unlikely(x) __builtin_expect(!!(x), 0) 


#define VALUE_SIZE 1024

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
        dump(L_WARN, "pcap_open_live warn: %s - %s", mp->netDev, ebuf);
              
        snprintf(mp->netDev, sizeof(mp->netDev), "%s", "any");
        mp->pd = pcap_open_live(mp->netDev, CAP_LEN, 0, 0, ebuf);
              
        if (NULL == mp->pd) {
            dump(L_ERR, "pcap_open_live error: %s - %s", "any", ebuf);
            return ERR;
        }
    }
              
    if (pcap_lookupnet(mp->netDev, &mp->localnet, &mp->netmask, ebuf) < 0) {
        dump(L_ERR, "pcap_open_live error: %s - %s", mp->netDev, ebuf);
        return ERR;
    }         
              
    dump(L_OK, "Listen Device is %s", mp->netDev);

    //snprintf(filter, sizeof(filter), "tcp port %d ", mp->mysqlPort);

    snprintf(filter, sizeof(filter), 
        "tcp port %d and tcp[tcpflags] & (tcp-push|tcp-ack) != 0", mp->mysqlPort);

    if (pcap_compile(mp->pd, &fcode, filter, 0, mp->netmask) < 0) {
        dump(L_ERR, "pcap_compile failed: %s", pcap_geterr(mp->pd));
        pcap_freecode(&fcode);
        return ERR;
    }

    if (pcap_setfilter(mp->pd, &fcode) < 0) {
        dump(L_ERR, "pcap_setfilter failed: %s", pcap_geterr(mp->pd));
        pcap_freecode(&fcode);
        return ERR;
    }

    pcap_freecode(&fcode);

    dump(L_OK, "%-20.20s%-16.16s%-10.10s%-10.10s%s", "timestamp", "latency(us)", "rows", "user", "sql");
    dump(L_OK, "%-20.20s%-16.16s%-10.10s%-10.10s%s", "---------", "-----------", "----", "----", "---");

    pcap_loop(mp->pd, -1, process_packet, (u_char *)mp);

    dump(L_ERR, "pcap_open_live error: %s - %s", mp->netDev, ebuf);
              
    pcap_close(mp->pd);

    return OK;
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
        
    case DLT_LINUX_SLL: // any come here
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

        // for loopback, dst & src are all local_address
        if (ip->ip_dst.s_addr == ip->ip_src.s_addr) { 
            if (dport == mp->mysqlPort) {
                incoming = 1; 
            } else 
                incoming = 0;
        }

        /* cmd packet & auth packet */

        /* internal 
         * receive auth, insert state = 1 (incoming = 1)
         * if state = 1 after ok packet state = 2, if error packet, remove entry (incoming = 0)
         * if state = 2 can go cmd and resultset packet
         * if state = 2 can fin, remove entry
         */

        /*
            Client                                      Server
            ==========================================================
                                                        handshake
            auth        AfterAuthPacket 
                        AfterOkPacket                   auth ok| error         

            sql         AfterSqlPacket 
                        AfterResultPacket               resultset              

            prepare     AfterPreparePacket      
                        AfterPrepareOkPacket            prepare-ok             

            execute     AfterSqlPacket
                        AfterResultPacket               resultset               

            stmt_close

        */
        char *sql, *user, *data;
        int cmd = -1;

        data = (char*) ((unsigned char *) tcp + tcp->doff * 4);

        if (incoming) {
            lport = dport;
            rport = sport;
           
            if (likely(is_sql(data, datalen, &user))) {
                /* COM_ packet */
                cmd = parse_sql(data, &sql, datalen);

                if (unlikely(cmd == COM_QUIT)) {

                    dump(L_DEBUG, "quit packet %s %d", sql, cmd);
                    hash_get_rem(mp->hash, ip->ip_dst.s_addr, ip->ip_src.s_addr, 
                        lport, rport, NULL, NULL, NULL);

                } else if (unlikely(cmd == COM_STMT_PREPARE)) {

                    dump(L_DEBUG, "prepare packet %s %d", sql, cmd);

                    hash_set(mp->hash, ip->ip_dst.s_addr, ip->ip_src.s_addr, 
                        lport, rport, tv, sql, cmd, NULL, AfterPreparePacket);

                } else if (unlikely(cmd == COM_STMT_CLOSE)) {

                    /* close param_type, param */
                    dump(L_DEBUG, "stmt close packet %s %d", sql, cmd);
                    hash_get_rem(mp->hash, ip->ip_dst.s_addr, ip->ip_src.s_addr, 
                        lport, rport, NULL, NULL, NULL);

                } else if (unlikely(cmd == COM_STMT_EXECUTE)) {

                    int stmt_id;
                    char *param_type = NULL;
                    uchar param[VALUE_SIZE];
                    param[0] = '\0';
                    char insert_param_type = 0;
                    int param_count;

                    /* stmt_id */
                    parse_stmt_id(data, datalen, &stmt_id);

                    /* param_count, param_type(possible) */
                    hash_get_param_count(mp->hash, ip->ip_dst.s_addr, ip->ip_src.s_addr, 
                        lport, rport, stmt_id, &param_count, &param_type);

                    assert(param_count > 0);

                    /* param_type in payload */
                    if (param_type == NULL)
                        insert_param_type = 1;

                    insert_param_type = parse_param(data, datalen, param_count, &param_type, &param[0]);

                    assert(param_type);

                    dump(L_DEBUG, "execute packet %s %d", sql, cmd);

                    hash_set_param(mp->hash, ip->ip_dst.s_addr, ip->ip_src.s_addr, 
                        lport, rport, tv, stmt_id, param, insert_param_type ? param_type:NULL, param_count);

                } else if (likely(cmd >= 0)) {

                    dump(L_DEBUG, "sql packet %s %d", sql, cmd);
                    hash_set(mp->hash, ip->ip_dst.s_addr, ip->ip_src.s_addr, 
                        lport, rport, tv, sql, cmd, NULL, AfterSqlPacket);

                } else 
                    assert(NULL);
            } else {
                /* auth packet */
                hash_set(mp->hash, ip->ip_dst.s_addr, ip->ip_src.s_addr, 
                    lport, rport, tv, NULL, cmd, user, AfterAuthPacket);
                dump(L_DEBUG, "auth packet %s", user);
            }
        } else {
            lport = sport;
            rport = dport;

            struct timeval tv2;
            time_t tv_t;
            struct tm *tm;
            tv_t = tv.tv_sec;
            tm = localtime(&tv_t);

            char tt[16];
            char *value = NULL;

            int num = parse_result(data, datalen);
            int status = hash_get(mp->hash, ip->ip_src.s_addr, ip->ip_dst.s_addr,
                lport, rport, &tv2, &sql, &user, &value);

            if (likely(AfterSqlPacket == status)) {

                // resultset
                if (value) {
                    // prepare-statement
                    snprintf(tt, sizeof(tt), "%d:%d:%d:%ld", 
                        tm->tm_hour, tm->tm_min, tm->tm_sec, tv2.tv_usec);

                    //printf("%s-%s\n", sql, value);
                    dump(L_OK, "%-20.20s%-16ld%-10ld%-10.10s %s [%s]", tt,
                        (tv.tv_sec - tv2.tv_sec) * 1000000 + (tv.tv_usec - tv2.tv_usec),
                        num, user,
                        sql, value);
                } else {
                    // normal statement
                    snprintf(tt, sizeof(tt), "%d:%d:%d:%ld", 
                        tm->tm_hour, tm->tm_min, tm->tm_sec, tv2.tv_usec);

                    dump(L_OK, "%-20.20s%-16d%-10ld%-10.10s %s", tt,
                        (tv.tv_sec - tv2.tv_sec) * 1000000 + (tv.tv_usec - tv2.tv_usec),
                        num, user,
                        sql);
                }
                //hash_print(mp->hash); 
            } else if (0 == status) {
                    dump(L_DEBUG, "handshake packet ");
            } else if (AfterAuthPacket == status) {
                if (unlikely(num == -1)) {
                    // auth error packet
                    dump(L_DEBUG, "error packet ");
                    hash_get_rem(mp->hash, ip->ip_src.s_addr, ip->ip_dst.s_addr, 
                        lport, rport, NULL, NULL, NULL);
                } else {
                    // auth ok packet
                    dump(L_DEBUG, "ok packet ");
                    hash_set(mp->hash, ip->ip_src.s_addr, ip->ip_dst.s_addr, 
                        lport, rport, tv, NULL, cmd, NULL, AfterOkPacket);
                }
            } else if (AfterPreparePacket == status) {
                    dump(L_DEBUG, "prepare ok packet ");

                    int stmt_id;
                    short param_count;
                    parse_prepare_ok(data, datalen, &stmt_id, &param_count);

                    hash_set_param_count(mp->hash, ip->ip_src.s_addr, ip->ip_dst.s_addr, 
                        lport, rport, stmt_id, param_count);
            }
        }

        break;
        
    default:
        break;
    }
    
    return 0;
}


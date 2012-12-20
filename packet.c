#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pcap.h>
#include <pcap/sll.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>

#include "utils.h"
#include "log.h"
#include "packet.h"
#include "address.h"
#include "mysqlpcap.h"
#include "protocol.h"
#include "hash.h"
#include "adlist.h"

#define likely(x)   __builtin_expect(!!(x), 1) 
#define unlikely(x) __builtin_expect(!!(x), 0) 

/* prepare statement param value length */
#define VALUE_SIZE 1024

/* mysql wait_timeout default value */
#define CONNECT_IDLE_TIME 8 * 3600 
/* each interval, will reload current ip address */
#define RELOAD_ADDRESS_INTERVAL 3600
/* poll wait time ms */
#define PCAP_POLL_TIMEOUT 3000

void process_packet(unsigned char *user, const struct pcap_pkthdr *header,
    const unsigned char *packet);
int process_ip(MysqlPcap *mp, const struct ip *ip, struct timeval tv);

int 
inbound(MysqlPcap *mp, char* data, uint32 datalen, 
    uint16 dport, uint16 sport, uint32 dst, uint32 src, struct timeval tv, struct tcphdr *tcp);

int 
outbound(MysqlPcap *mp, char* data, uint32 datalen, 
    uint16 dport, uint16 sport, uint32 dst, uint32 src, struct timeval tv, struct tcphdr *tcp, char *srcip);

char GoutputPacketStatus = '0';

void sigusr1_handler(int sig) {
    if (sig == SIGUSR1) GoutputPacketStatus = '1';
}
/*
char GreloadAddress = '0';

void sigalarm_handler(int sig) {
    if (sig == SIGALRM) GreloadAddress = '1';
}
*/

/*
    if dev has set, use it, else use 'any'
    if dev not exists use 'any'
*/
int
start_packet(MysqlPcap *mp) {

    struct bpf_program fcode;
    char ebuf[PCAP_ERRBUF_SIZE];
    int ret;

    struct sigaction act;

    act.sa_handler = sigusr1_handler;
    act.sa_flags = SA_RESTART;
    sigemptyset(&act.sa_mask);
    sigaddset(&act.sa_mask, SIGUSR1);
    sigaction(SIGUSR1, &act, NULL);

    mp->pd = pcap_create(mp->netDev, ebuf);
    if (NULL == mp->pd) {
        dump(L_ERR, "pcap_open_live error: %s - %s", mp->netDev, ebuf);
        return ERR;
    }

    if (pcap_lookupnet(mp->netDev, &mp->localnet, &mp->netmask, ebuf) < 0) {
        dump(L_ERR, "pcap_open_live error: %s - %s", mp->netDev, ebuf);
        return ERR;
    }

    ret = pcap_set_snaplen(mp->pd, CAP_LEN);
    ASSERT(ret == 0);
    ret = pcap_set_timeout(mp->pd, PCAP_POLL_TIMEOUT);
    ASSERT(ret == 0);

    /* set pcap buffer size is 32m, decline drop percentage */
    ret = pcap_set_buffer_size(mp->pd, 1024 * 1024 * 32);
    ASSERT(ret == 0);

    ret = pcap_activate(mp->pd);
    ASSERT(ret >= 0);

    snprintf(mp->filter, sizeof(mp->filter), 
        "tcp port %d and tcp[tcpflags] & (tcp-push|tcp-ack) != 0", mp->mysqlPort);

    if (pcap_compile(mp->pd, &fcode, mp->filter, 0, mp->netmask) < 0) {
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

    dump(L_OK, "Listen Device is %s, Filter is %s", mp->netDev, mp->filter);

    if (strlen(mp->cacheConfigFileName) == 0) {
        mp->addCache(mp, "Listen Device is %s, Filter is %s\n", mp->netDev, mp->filter);

        if (mp->isShowSrcIp == 1) {
            mp->addCache(mp, "%-20.20s%-17.17s%-16.16s%-10.10s%-10.10s%s\n", 
                "timestamp", "source ip ",    "latency(us)", "rows", "user", "sql");
            mp->addCache(mp, "%-20.20s%-17.17s%-16.16s%-10.10s%-10.10s%s\n", 
                "---------", "---------------", "-----------", "----", "----", "---");
        } else {
            mp->addCache(mp, "%-20.20s%-16.16s%-10.10s%-10.10s%s\n", "timestamp", "latency(us)", "rows", "user", "sql");
            mp->addCache(mp, "%-20.20s%-16.16s%-10.10s%-10.10s%s\n", "---------", "-----------", "----", "----", "---");
        }

        mp->flushCache(mp, 1);
    }

    while(1) {
        ret = pcap_dispatch(mp->pd, -1, process_packet, (u_char*)mp);
        ASSERT(ret >=0);

        /* output drop packet percentage */
        if (GoutputPacketStatus == '1') {
            GoutputPacketStatus = '0'; 
            struct pcap_stat ps;
            pcap_stats(mp->pd, &ps);
            dump(L_OK, "recv: %u, drop: %u", ps.ps_recv, ps.ps_drop); 
        }

        /* 
         * avert each return systemcall time, only poll timeout call it
         * each 3 seconds call time(NULL) in maximum
         * ret > 0, we use mp->fakeNow as now, max deviation is smaller than 3 seconds
        */
        if (ret == 0) {
            mp->fakeNow = time(NULL);
            dump(L_DEBUG, "timeout~~~~ %d %ld", ret, mp->fakeNow);
        }
        /* flush cache, actually is flush by user */
        mp->flushCache(mp, 0);
        /* 
         * each INTERVAL do below
         * 1. reload address 
         * 2. delete idle connection, interval is mysql wait timeout 
         * 3. print drop percentage
        */
        ASSERT(mp->lastReloadAddressTime <= mp->fakeNow);
        if (mp->fakeNow - mp->lastReloadAddressTime > RELOAD_ADDRESS_INTERVAL) {
            /* if specify address, skip reload address */
            if (NULL == mp->address) {
                dump(L_OK, " reload address ");
                free_addresses(mp->al);
                mp->al = get_addresses();
                mp->lastReloadAddressTime = time(NULL);
                mp->fakeNow = mp->lastReloadAddressTime;
            }

            dump(L_DEBUG, " delete idle connection ");
            hash_delete_idle(mp->hash, mp->fakeNow, 8 * RELOAD_ADDRESS_INTERVAL);

            struct pcap_stat ps;
            pcap_stats(mp->pd, &ps);
            dump(L_OK, "recv: %u, drop: %u", ps.ps_recv, ps.ps_drop); 
        }

        /* shrink session->sql && session->param mem */
        /*
        hash_shrink_mem(mp->hash, header->ts, 60);
        dump(L_DEBUG, " shrink mem");
        */
    }

    pcap_close(mp->pd);

    return OK;
}

void
process_packet(u_char *user, const struct pcap_pkthdr *header,
    const u_char *packet) {

    MysqlPcap *mp = (MysqlPcap *) user;

    /*
    struct pcap_stat ps;
    pcap_stats(mp->pd, &ps);
    printf("recv:%u-drop:%u-ifdrop:%u\n", ps.ps_recv, ps.ps_drop, ps.ps_ifdrop);
    */

    const struct sll_header *sll;
    const struct ether_header *ether_header;
    const struct ip *ip;
    unsigned short packet_type;

    /* Parse packet */
    switch (pcap_datalink(mp->pd)) {

    case DLT_LINUX_SLL: /* device 'any' */
        sll = (struct sll_header *) packet;
        packet_type = ntohs(sll->sll_protocol); /* ETHERTYPE_IP */
        ip = (const struct ip *) (packet + sizeof(struct sll_header));
        break;

    case DLT_EN10MB: /* device 'eth* | lo ' here */
        ether_header = (struct ether_header *) packet;
        packet_type = ntohs(ether_header->ether_type);
        ip = (const struct ip *) (packet + sizeof(struct ether_header));
        break;

    case DLT_RAW:
        packet_type = ETHERTYPE_IP; //This is raw ip
        ip = (const struct ip *) packet;
        break;

    default:
        dump(L_ERR, "whats's packet?");
        return;
    }

    if (packet_type != ETHERTYPE_IP)
        return;

    mp->packetSeq++;
    mp->fakeNow = header->ts.tv_sec; /* use packet time instead of time systemcall */
    process_ip(mp, ip, header->ts);
}

int
process_ip(MysqlPcap *mp, const struct ip *ip, struct timeval tv) {

    char src[16], dst[16], *addr = NULL;
    char incoming;
    uint32 len;

    addr = inet_ntoa(ip->ip_src);
    strncpy(src, addr, 15);
    src[15] = '\0';

    addr = inet_ntoa(ip->ip_dst);
    strncpy(dst, addr, 15);
    dst[15] = '\0';

    if (is_local_address(mp->al, ip->ip_src))
        incoming = '0';
    else if (is_local_address(mp->al, ip->ip_dst))
        incoming = '1';
    else
        return ERR;

    len = htons(ip->ip_len);
    ASSERT(len > 0);

    switch (ip->ip_p) {
        struct tcphdr *tcp;
        uint16 sport, dport;
        uint32 datalen;

    case IPPROTO_TCP:
        tcp = (struct tcphdr *) ((uchar *) ip + sizeof(struct ip));

#if defined(__FAVOR_BSD)
        sport = ntohs(tcp->th_sport);
        dport = ntohs(tcp->th_dport);
        datalen = len - sizeof(struct ip) - tcp->th_off * 4;    // 4 bits offset 
#else
        sport = ntohs(tcp->source);
        dport = ntohs(tcp->dest);
        datalen = len - sizeof(struct ip) - tcp->doff * 4;
#endif
        ASSERT((sport > 0) && (dport > 0));

        // Capture only "data" packets, ignore TCP control
        if (datalen == 0)
            break;
        /*
         * for loopback, dst & src are all local_address
         * so use port to distinguish 
        */
        if (ip->ip_dst.s_addr == ip->ip_src.s_addr) { 
            if (dport == mp->mysqlPort) {
                incoming = '1'; 
            } else 
                incoming = '0';
        }

        char *data = (char*) ((uchar *) tcp + tcp->doff * 4);

        dump(L_DEBUG,"is_in:%c-datalen:%d-tcp:%u %u-%u", incoming, datalen, tcp->seq, dport,sport);

        if (incoming == '1') {
            /* ignore remote MySQL port connect locate random port */
            if ((dport != mp->mysqlPort))
                break;
            inbound(mp, data, datalen, dport, sport, ip->ip_dst.s_addr, ip->ip_src.s_addr, tv, tcp); 
        } else {
            /* ignore locate random port connect remote MySQL port */
            if (sport != mp->mysqlPort)
                break;
            outbound(mp, data, datalen, dport, sport, ip->ip_dst.s_addr, ip->ip_src.s_addr, tv, tcp, dst); 
        }
        mp->is_in = incoming;
        mp->datalen = datalen;
        mp->tcp_seq = tcp->seq;

        /* internal 
         * receive auth, insert state = 1 (incoming = 1)
         * if state = 1 after ok packet state = 2, if error packet, remove entry (incoming = 0)
         * if state = 2 can go cmd and resultset packet
         * if state = 2 can fin, remove entry
         */

        /*
            Client                                      Server
            ==========================================================
                                                    <          handshake
            auth        >   AfterAuthPacket 
                            AfterOkPacket           <          auth ok| error

            1.sql       >   AfterSqlPacket 
                            AfterResultPacket       <          resultset

            1.prepare   >   AfterPreparePacket
                            AfterPrepareOkPacket    <          prepare-ok

            2.execute   >   AfterSqlPacket
                            AfterResultPacket       <          resultset

            stmt_close  >

            ----------------------secure-auth--------------------
                                                <          handshake
            auth        >   AfterAuthPacket 
                            AfterAuthEofPacket  <          eof packet
            password    >   AfterAuthPwPacket
                            AfterOkPacket       <          auth ok| error


        */

        break;

    default:
        break;
    }
    return OK;
}

int 
inbound(MysqlPcap *mp, char* data, uint32 datalen, 
    uint16 dport, uint16 sport, uint32 dst, uint32 src, struct timeval tv, struct tcphdr *tcp) {

    char *sql = NULL, *user = NULL;
    int cmd = ERR;
    int ret = ERR;
    int status = ERR;
    uint32 sqlSaveLen = 0;
    uint32_t *tcp_seq = NULL;

    ASSERT(datalen > 0);
    ASSERT(data);
    ASSERT(mp && mp->hash && mp->pd);

    uint16 lport, rport;

    lport = dport;
    rport = sport;

    status = hash_get_status(mp->hash, dst, src,
        lport, rport, &sql, &sqlSaveLen, &tcp_seq);

    if ((status == AfterAuthCompressPacket) || (status == AfterFilterUserPacket)) {
        return ERR; 
    }

    if ((status == AfterAuthEofPacket)) {
        /* here is scramble232 password */ 
        hash_set(mp->hash, dst, src, 
            lport, rport, tv, NULL, 0, NULL, 0, AfterAuthPwPacket);
        return OK;
    }

    if (AfterOkPacket == status) {
        *tcp_seq = ntohl(tcp->seq) + datalen;
        dump(L_DEBUG, "after resultset first receive packet");
    }
    /* only filter sql repeat packet */
    if (AfterSqlPacket == status) {
        if (*tcp_seq == 0) {
            *tcp_seq =ntohl(tcp->seq) + datalen;
             dump(L_DEBUG, "first receive packet");
        } else if (*tcp_seq == ntohl(tcp->seq)) {
            *tcp_seq = ntohl(tcp->seq) + datalen;
            dump(L_DEBUG, "sql continues packet %u", datalen);
        } else {
            if (*tcp_seq > ntohl(tcp->seq)) {
                dump(L_DEBUG, "sql repeat packet %u", datalen);
                return ERR;
            }
            return ERR;
        }
    }
    if (likely((cmd = is_sql(data, datalen, &user, sqlSaveLen)) >= 0)) {
        ASSERT(user == NULL);
        /* compress protocol */
        if ((COM_QUIT <= cmd) && (cmd < COM_END)) {
            if (cmd == COM_QUIT) {
                if (datalen != 5) {
                    dump(L_OK, " compress sql ");
                    hash_set(mp->hash, dst, src, 
                        lport, rport, tv, "compress sql", 0, NULL, ret, AfterAuthCompressPacket);
                    return ERR;
                }
            }
            if ((cmd != COM_STMT_EXECUTE) && (status != AfterPreparePacket) 
                && (datalen > 7 ) && ( data[7] == '\0')) {
                dump(L_OK, " compress sql ");
                hash_set(mp->hash, dst, src, 
                    lport, rport, tv, "compress sql", 0, NULL, ret, AfterAuthCompressPacket);
                return ERR;
            }
        } else {
            dump(L_OK, " compress sql ");
            hash_set(mp->hash, dst, src, 
                lport, rport, tv, "compress sql", 0, NULL, ret, AfterAuthCompressPacket);
            return ERR;
        }

        /* COM_ packet */
        if (unlikely(cmd == COM_QUIT)) {

            dump(L_DEBUG, "quit packet %s %d, so remove entry", sql, cmd);
            hash_get_rem(mp->hash, dst, src, 
                lport, rport, NULL, NULL, NULL);
        } else if (unlikely(cmd == COM_STMT_PREPARE)) {

            ret = parse_sql(data, datalen, &sql, sqlSaveLen);
            /* TODO prepare sql is possible too long */
            ASSERT(ret == 0);
            ASSERT(sql);
            /* exists length 0 sql */
            //ASSERT(strlen(sql) > 0);
            dump(L_DEBUG, "prepare packet %s %d", sql, cmd);
            hash_set(mp->hash, dst, src, 
                lport, rport, tv, sql, cmd, NULL, ret, AfterPreparePacket);
        } else if (unlikely(cmd == COM_STMT_CLOSE)) {

            /* #TODO, only remove stmt_id, not session */
            dump(L_DEBUG, "stmt close packet %s %d", sql, cmd);
            //hash_get_rem(mp->hash, dst, src, lport, rport, NULL, NULL, NULL);
        } else if (unlikely(cmd == COM_STMT_EXECUTE)) {
            /*
             *  two state:
             *      1. type and value, true
             *      2. only value, can get type from hash, true
             *      3. only value , cant get type from hash, false
            */
            int stmt_id = ERR;
            char *param_type = NULL;
            char *new_param_type = NULL;
            char param[VALUE_SIZE];
            param[0] = '\0';
            int param_count = ERR;

            /* stmt_id */
            parse_stmt_id(data, datalen, &stmt_id);
            if (stmt_id <= 0) {
                dump(L_DEBUG, "stmt is error, you cant execute");
                return ERR;
            }
            ASSERT(stmt_id > 0);

            /* is param_count(must), param_type(possible) saved ?*/
            hash_get_param_count(mp->hash, dst, src, 
                lport, rport, stmt_id, &param_count, &param_type);

            if (param_count != ERR) {
                ASSERT(param_count >= 0);
                /* prepare cant find, param_type in payload */
                if (param_count > 0)
                    new_param_type = parse_param(data, datalen, param_count, param_type, param, sizeof(param));

                if (param_count > 0) ASSERT(param[0]);
                if ((param_type == NULL) && (new_param_type == NULL) && (param_count > 0)) {
                    dump(L_DEBUG, "execute packet, but param_type cant find");
                    return ERR;
                }
                dump(L_DEBUG, "execute packet %s %d %s", sql, cmd, param);
                hash_set_param(mp->hash, dst, src, 
                    lport, rport, tv, stmt_id, param, new_param_type? new_param_type:param_type, param_count);
            } else {
                /* is stmt,  sql cant find, possible pcap enter later than sql */ 
                dump(L_DEBUG, " stmt, but start pcap too late");
                return OK;
            }
        } else if (unlikely(cmd == COM_SLEEP)) {
            dump(L_DEBUG, "sleep ");
            hash_set(mp->hash, dst, src, 
                lport, rport, tv, "sleep", cmd, NULL, 0, AfterSqlPacket);
        } else if (unlikely(cmd == COM_PING)) {
            dump(L_DEBUG, "ping ");
            hash_set(mp->hash, dst, src, 
                lport, rport, tv, "ping", cmd, NULL, 0, AfterSqlPacket);
        } else if (unlikely(cmd == COM_BINLOG_DUMP)) {
            dump(L_DEBUG, "binlog dump");
            hash_set(mp->hash, dst, src, 
                lport, rport, tv, "binlog dump", cmd, NULL, 0, AfterSqlPacket);
        } else if (unlikely(cmd == COM_STATISTICS)) {
            dump(L_DEBUG, "statistics");
            hash_set(mp->hash, dst, src, 
                lport, rport, tv, "statistics", cmd, NULL, 0, AfterSqlPacket);
        } else if (unlikely(cmd == COM_SET_OPTION)) {
            dump(L_DEBUG, "set option");
            hash_set(mp->hash, dst, src, 
                lport, rport, tv, "set option", cmd, NULL, 0, AfterSqlPacket);
        } else if (unlikely(cmd == COM_SHUTDOWN)) {
            dump(L_DEBUG, "shutdown");
            hash_set(mp->hash, dst, src, 
                lport, rport, tv, "shutdown", cmd, NULL, 0, AfterSqlPacket);
        } else if (unlikely(cmd == COM_INIT_DB)) {
            dump(L_DEBUG, "init_db");
            hash_set(mp->hash, dst, src, 
                lport, rport, tv, "init_db", cmd, NULL, 0, AfterSqlPacket);
        } else if (likely(cmd > 0)) {
            //ASSERT((cmd == COM_QUERY) || (cmd == COM_INIT_DB));
            /*
                sqlLen 3000
                1. 1400 save sql and sqlSaveLen 1600
                2. 1400 sqlSaveLen 200
                3. 200 
            */
            ret = parse_sql(data, datalen, &sql, sqlSaveLen);
            ASSERT(ret >= 0);
            if (ret > 0) {
                dump(L_DEBUG, "sql is too long big than a packet");
            }

            ASSERT(sql);
            //ASSERT(strlen(sql)>0);
            dump(L_DEBUG, "sql packet [%s] %d", sql, cmd);
            if (sqlSaveLen > 0) { 
                hash_set_sql_len(mp->hash, dst, src, 
                    lport, rport, ret);
            } else {
                hash_set(mp->hash, dst, src, 
                    lport, rport, tv, sql, cmd, NULL, ret, AfterSqlPacket);
            }
        } else {
            dump(L_ERR, "why here %d %u %u %s", cmd, status, datalen, sql);
            ASSERT(NULL);
        }
    } else {
        ASSERT(user);
        ASSERT((cmd == -2) || (cmd == -1));
        /* auth packet */
        if (cmd == -1) {
            if (mp->focusUser) {
                if (NULL == listSearchKey(mp->focusUser, user)) {
                    dump(L_DEBUG, "user:%s is not in focus", user);
                    hash_set(mp->hash, dst, src, 
                        lport, rport, tv, NULL, cmd, user, 0, AfterFilterUserPacket);
                    return ERR;
                }
            }
            if (mp->filterUser) {
                if (listSearchKey(mp->filterUser, user)) {
                    dump(L_DEBUG, "user:%s is in filter", user); 
                    hash_set(mp->hash, dst, src, 
                        lport, rport, tv, NULL, cmd, user, 0, AfterFilterUserPacket);
                    return ERR;
                }
            }

            hash_set(mp->hash, dst, src, 
                lport, rport, tv, NULL, cmd, user, 0, AfterAuthPacket);
            dump(L_DEBUG, "auth packet %s", user);
        } else {
            hash_set(mp->hash, dst, src, 
                lport, rport, tv, NULL, cmd, user, 0, AfterAuthCompressPacket);
            dump(L_OK, "auth packet %s is compress, will filter", user);
        }
    }
    return OK;
}

int 
outbound(MysqlPcap *mp, char *data, uint32 datalen, 
    uint16 dport, uint16 sport, uint32 dst, uint32 src, struct timeval tv, struct tcphdr *tcp, char *srcip) {

    char *sql = NULL, *user = NULL;
    int cmd = ERR;
    int ret = ERR;

    uint16 lport, rport;

    lport = sport;
    rport = dport;

    struct timeval tv2;
    time_t tv_t;
    struct tm *tm;
    tv_t = tv.tv_sec;
    tm = localtime(&tv_t);

    char tt[16];
    uchar **lastData = NULL;
    size_t *lastDataSize = NULL;
    ulong *lastNum = NULL;
    enum ProtoStage *ps = NULL;

    char *value = NULL;
    uint32_t *tcp_seq = NULL;

    /* TODO other hash_set must clear lastNum lastData, lastDataSize */
    int status = hash_get(mp->hash, src, dst,
        lport, rport, &tv2, &sql, &user, &value, &lastData, 
        &lastDataSize, &lastNum, &ps, &tcp_seq, &cmd);

    if ((status == AfterAuthCompressPacket) || (status == AfterFilterUserPacket)) {
        return ERR; 
    }
    if (status > 0) {
        if (*tcp_seq == 0) {
            *tcp_seq =ntohl(tcp->seq) + datalen;
            dump(L_DEBUG, "first receive packet");
        } else {
            if (*tcp_seq == ntohl(tcp->seq)) {
                //printf("continue packet expect is %u, now is %u \n", *tcp_seq, ntohl(tcp->seq)); 
                *tcp_seq = ntohl(tcp->seq) + datalen;
            } else {
                if (*tcp_seq > ntohl(tcp->seq)) {
                    dump(L_DEBUG, "bond repeat packet");
                    return ERR;
                }

                struct pcap_stat ps;
                pcap_stats(mp->pd, &ps);
                dump(L_ERR, " error packet expect %u but %u drops:%u", *tcp_seq , ntohl(tcp->seq), ps.ps_drop); 

                // skip error packet 
                if (*lastData) {
                    free(*lastData);
                    *lastData = NULL;
                }
                *lastDataSize = 0;
                *lastNum = 0;
                // fast over this packet
                return ERR;
            }
        }
    }

    if (likely(AfterSqlPacket == status)) {
        ASSERT(cmd >= 0);
        ASSERT(sql);
        //ASSERT(strlen(sql) > 0);

        long num;
        ulong latency;

        if ((cmd == COM_BINLOG_DUMP) || (cmd == COM_SET_OPTION) || (cmd == COM_PING)
            || (cmd == COM_STATISTICS) || (cmd == COM_SLEEP) || (cmd == COM_SHUTDOWN)) {
            //eof packet or error packet, skip it 
           num = 1;
        } else {
            //resultset packet
           num = parse_result(data, datalen, lastData, lastDataSize, lastNum, ps);
        }

        if (num == -3) {
            dump(L_ERR, "@@@@@@@@@@@@@@@@@@@ %s %d", sql, cmd); 
        }
        ASSERT((num == -2) || (num >= 0) || (num == -1));
        latency = (tv.tv_sec - tv2.tv_sec) * 1000000 + (tv.tv_usec - tv2.tv_usec);
        // resultset
        if (value) {
            // prepare-statement
            snprintf(tt, sizeof(tt), "%d:%d:%d:%ld", 
                tm->tm_hour, tm->tm_min, tm->tm_sec, tv2.tv_usec);

            if (mp->isShowSrcIp == 1) {
                mp->addCache(mp, "%-20.20s%-17.17s%-16lu%-10ld%-10.10s %s [%s]\n", tt,
                    srcip, latency , num, user, sql, value);
            } else {
                mp->addCache(mp, "%-20.20s%-16lu%-10ld%-10.10s %s [%s]\n", tt,
                    latency, num, user, sql, value);
            }
        } else {
            // normal statement
            snprintf(tt, sizeof(tt), "%d:%d:%d:%ld", 
                tm->tm_hour, tm->tm_min, tm->tm_sec, tv2.tv_usec);

            if (mp->isShowSrcIp == 1) {
                mp->addCache(mp, "%-20.20s%-17.17s%-16lu%-10ld%-10.10s %s\n", tt,
                    srcip, latency, num, user, sql);
            } else {
                mp->addCache(mp, "%-20.20s%-16lu%-10ld%-10.10s %s\n", tt,
                    latency, num, user, sql);
            }
        }
        if (num >= -1) {
            hash_set(mp->hash, src, dst, 
                lport, rport, tv, sql, cmd, user, 0, AfterOkPacket);
        }
        //hash_print(mp->hash); 
    } else if (0 == status) {
            dump(L_DEBUG, "handshake packet or out packet but cant find session ");
    } else if ((AfterAuthPacket == status) || (AfterAuthPwPacket == status)) {
        long state = parse_result(data, datalen, NULL, NULL, NULL, NULL);
        ASSERT( (state == ERR) || (state == OK) || (state == -3));
        if (unlikely(state == ERR)) {
            dump(L_DEBUG, "auth error packet ");
            hash_get_rem(mp->hash, src, dst, 
                lport, rport, NULL, NULL, NULL);
        } else if (state == -3) {
            dump(L_DEBUG, "secure auth eof packet ");
            hash_set(mp->hash, src, dst, 
                lport, rport, tv, NULL, cmd, NULL, 0, AfterAuthEofPacket);
        } else {
            dump(L_DEBUG, "auth ok packet ");
            hash_set(mp->hash, src, dst, 
                lport, rport, tv, NULL, cmd, NULL, 0, AfterOkPacket);
        }
    } else if (AfterPreparePacket == status) {
        int stmt_id = ERR;
        int param_count = ERR;

        /* only handle first packet, skip field packet and next */
        ret = parse_prepare_ok(data, datalen, &stmt_id, &param_count);
        ASSERT(ret == 0);
        ASSERT(stmt_id > 0);
        ASSERT(param_count >= 0);
        hash_set_param_count(mp->hash, src, dst, 
            lport, rport, stmt_id, param_count);
        dump(L_DEBUG, "prepare ok packet %d %d", stmt_id, param_count);
    } else {
        dump(L_ERR, "why here %d %s %s", status, user, sql);
        ASSERT(NULL); 
    }
    return OK;
}


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

#if !defined(PROCESS_PACKET_H)
#define PROCESS_PACKET_H

#include <netinet/ip.h>
#include <pcap.h>

#include "mysqlpcap.h"

int start_packet(MysqlPcap * mp);

void process_packet(unsigned char *, const struct pcap_pkthdr *,
                    const unsigned char *);
int process_ip(MysqlPcap*, const struct ip *ip, struct timeval tv);




enum enum_server_command
{  
    //0
    COM_SLEEP, COM_QUIT, COM_INIT_DB, COM_QUERY, COM_FIELD_LIST, 
    //5
    COM_CREATE_DB, COM_DROP_DB, COM_REFRESH, COM_SHUTDOWN, COM_STATISTICS,
    //10
    COM_PROCESS_INFO, COM_CONNECT, COM_PROCESS_KILL, COM_DEBUG, COM_PING,
    //15
    COM_TIME, COM_DELAYED_INSERT, COM_CHANGE_USER, COM_BINLOG_DUMP, COM_TABLE_DUMP, 
    //20
    COM_CONNECT_OUT, COM_REGISTER_SLAVE, COM_STMT_PREPARE, COM_STMT_EXECUTE, COM_STMT_SEND_LONG_DATA, 
    //25
    COM_STMT_CLOSE, COM_STMT_RESET, COM_SET_OPTION, COM_STMT_FETCH, COM_DAEMON,
  /* don't forget to update const char *command_name[] in sql_parse.cc */
   
  /* Must be last */
  COM_END
}; 












#endif

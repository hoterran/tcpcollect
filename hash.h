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
 
#if !defined(STATS_HASH_H)
#define STATS_HASH_H

enum SessionStatus {    AfterAuthPacket = 1, 
                        AfterOkPacket,
                        AfterSqlPacket,
                        AfterHalfSqlPacket,
                        AfterResultPacket,
                        AfterPreparePacket,
                        AfterPrepareOkPacket,
                        AfterAuthCompressPacket,
                        AfterFilterUserPacket,

                        AfterAuthEofPacket,
                        AfterAuthPwPacket,
                        };

struct hash;

struct hash *hash_new(void);
void hash_del(struct hash *hash);
int hash_free(struct hash *hash);

int hash_get_status(struct hash *hash,
     uint32_t laddr, uint32_t raddr, uint16_t lport, uint16_t rport,
     char **sql, uint32 *sqlSaveLen, uint32 **tcp_seq);

int hash_get(struct hash *hash,
    uint32_t laddr, uint32_t raddr, uint16_t lport, uint16_t rport,
    struct timeval *result, char **sql, char **user, char **db, char **value,
    uchar ***lastData, size_t **lastDataSize, ulong **lastNum, enum ProtoStage **ps, uint **tcpseq, int *cmd);

int hash_get_rem(struct hash *hash,
         uint32_t laddr, uint32_t raddr, uint16_t lport, uint16_t rport);
int hash_set(struct hash *hash,
         uint32_t laddr, uint32_t raddr, uint16_t lport, uint16_t rport,
         struct timeval value, char* sql, int cmd, char *user, char *db, uint32_t sqlSaveLen, enum SessionStatus status);

int hash_set_sql_len(struct hash *hash,
         uint32_t laddr, uint32_t raddr, uint16_t lport, uint16_t rport,
         uint32_t sqlSaveLen, int status);
         
int hash_clean(struct hash *hash, unsigned long min);

void hash_delete_idle(struct hash* hash, time_t now, int idle_time);

void hash_print(struct hash* hash);


int
hash_set_stmt (struct hash *hash, 
         uint32_t laddr, uint32_t raddr, uint16_t lport, uint16_t rport,
         enum SessionStatus status);

int 
hash_set_param_count (struct hash *hash,
         uint32_t laddr, uint32_t raddr, uint16_t lport, uint16_t rport,
         int stmt_id, int param_count);

int
hash_set_param (struct hash *hash, 
         uint32_t laddr, uint32_t raddr, uint16_t lport, uint16_t rport,struct timeval value, int stmt_id,
          char *param, char *param_type, int param_count);

int
hash_get_param_count(struct hash *hash,
         uint32_t laddr, uint32_t raddr, uint16_t lport, uint16_t rport,
         int stmt_id, int *param_count, char **param_type);

#endif

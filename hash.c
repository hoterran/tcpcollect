#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <string.h>

#include "utils.h"
#include "mysqlpcap.h"
#include "protocol.h"
#include "hash.h"
#include "log.h"

#define INITIAL_HASH_SZ     2053
#define MAX_LOAD_PERCENT    65
#define SQL_MAX_LEN         2048
#define VALUE_MAX_LEN       1024

/* 1: receive auth packet 2: recieve ok packet start work */

struct session {
    uint32_t laddr, raddr;
    uint16_t lport, rport;
    
    struct timeval tv;

    char *sql; // maxsize SQL_MAX_LEN
    uint32_t sqlSaveLen; 
    char *user;
    char *db;
    int cmd;
    enum SessionStatus status; 

    uchar *lastData;
    size_t lastDataSize;
    ulong lastNum;
    enum ProtoStage ps;      /* 0 is handle field_number, 1 is eof step, 2 is resultset step */
    uint32_t  tcp_seq;
    
    struct session *next;

    ulong stmt_id;
    char is_long_data; /* if this flag, no parse_param, TODO next version */
    int param_count;

    /* each param count 2 bytes */
    void *param_type;

    char *param;
};

struct hash {
    struct session *sessions;
    unsigned long sz, count;
};

typedef void (*funcp)(struct hash *hash, struct session *session, void *arg);

static int hash_loop(struct hash *hash, funcp func, void *arg);

static void funcp_print(struct hash *hash, struct session *session, void *arg) {
    dump(L_OK, "user:%s-sql:%s %u %u %u %u %u %d", session->next->user, session->next->sql, 
        session->next->tv.tv_sec, session->next->lport, session->next->rport, 
        session->next->laddr, session->next->raddr, session->next->status);
}

static void funcp_del(struct hash *hash, struct session *session, void *arg) {
    ASSERT(session->next);
    struct session *next = session->next->next;
    if (session->next->sql) {
        free(session->next->sql);
        session->next->sql = NULL;
    }
    if (session->next->user) {
        free(session->next->user);
        session->next->user = NULL;
    }
    if (session->next->db) {
        free(session->next->db);
        session->next->db = NULL;
    }
    if (session->next->param) {
        free(session->next->param);
        session->next->param = NULL;
    }
    if (session->next->param_type) {
        free(session->next->param_type);
        session->next->param_type = NULL;
    }
    if (session->next->lastData) {
        free(session->next->lastData);
        session->next->lastData = NULL;
    }

    free(session->next);
    session->next = next;
    
    hash->count--;
}

struct Arg {time_t now; int idle_time;};

static void funcp_check_count(struct hash *hash, struct session *session, void  *i) {
    int *i2 = (int*)i;
    (*i2)++;
}

/* hash record will delete if idle time longer than 300s */
static void funcp_delete_idle(struct hash *hash, struct session *session, void *arg) {
  
    /* arg */ 
    struct Arg *a = arg;
    time_t now = a->now;
    int idle_time = a->idle_time;
   
    time_t tv_t;
    tv_t = session->next->tv.tv_sec;

    /* compare */ 
    if ( (now - tv_t) >= idle_time) {
        dump(L_OK, "del this slot [user:%s db:%s]", session->next->user, session->next->db);
        funcp_del(hash, session, NULL);
    }
}

void hash_clean(struct hash* hash) {
    hash_loop(hash, funcp_del, NULL);
    hash_del(hash);
}

void hash_delete_idle(struct hash* hash, time_t now, int idle_time) {
    struct Arg a ;
    a.now = now;
    a.idle_time = idle_time;
    hash_loop(hash, funcp_delete_idle, (void*)&a);
}

void hash_print(struct hash* hash) {
    hash_loop(hash, funcp_print, NULL);
}

void hash_stat(struct hash* hash) {
    dump(L_OK, "hash stat %u-%u", hash->sz, hash->count);
}

void hash_check_count(struct hash* hash) {
    int i = 0;
    hash_loop(hash, funcp_check_count, (void*)&i);
    ASSERT(hash->count == i);
}

/* general hash iterator */
static int hash_loop(struct hash *hash, funcp func, void *arg) {
    unsigned long i;
    for (i = 0; i < hash->sz; i ++) {
        struct session *session;
       
        for (session = hash->sessions + i; session && session->next;session = session->next) {
            if (session->next) func(hash, session, arg);
        }
    }
    return 0;
}

static unsigned long
    hash_fun(uint32_t laddr, uint32_t raddr, uint16_t lport, uint16_t rport);
static int hash_set_internal(struct session *sessions, unsigned long sz,
        uint32_t laddr, uint32_t raddr, uint16_t lport, uint16_t rport,
        struct timeval tv, char *sql, int cmd, char *user, char *db, uint32 sqlSaveLen, enum SessionStatus status);
static int hash_load_check(struct hash *hash);
static unsigned long hash_newsz(unsigned long sz);
    
unsigned long initial_hash_sz = INITIAL_HASH_SZ;

struct hash *
hash_new(void) {
    struct hash *ret;
    
    ret = malloc(sizeof(struct hash));
    if (!ret)
        abort();
    
    ret->sz = initial_hash_sz;
    ret->count = 0;
    
    // Don't change following ret->sz for initial_hash_sz. That wouldn't be
    // very thread_safe (not that the whole module is :)
    ret->sessions = malloc(ret->sz * sizeof(struct session));
    if (!ret->sessions)
        abort();
    memset(ret->sessions, 0, ret->sz * sizeof(struct session));
    
    return ret;
}
int
hash_free(struct hash* hs) {
    return 0;
}

void
hash_del(struct hash *hash) {
    free(hash->sessions);
    free(hash);
}

int hash_get_status(struct hash *hash,
     uint32_t laddr, uint32_t raddr, uint16_t lport, uint16_t rport,
     char **sql, uint32_t *sqlSaveLen, uint32_t **tcp_seq, int *cmd) {

    struct session *session;
    unsigned long port;
    
    port = hash_fun(laddr, raddr, lport, rport) % hash->sz;
    for (session = hash->sessions + port; session->next; session = session->next)
        if (
            session->next->raddr == raddr &&
            session->next->laddr == laddr &&
            session->next->rport == rport &&
            session->next->lport == lport
        ) {
            *sql = session->next->sql;
            *sqlSaveLen = session->next->sqlSaveLen;
            *tcp_seq = &(session->next->tcp_seq);
            *cmd = session->next->cmd;

            return session->next->status;
        }
        
    return 0;
 }

int
hash_get(struct hash *hash,
         uint32_t laddr, uint32_t raddr, uint16_t lport, uint16_t rport,
         struct timeval *result, char **sql, char **user, char **db, char **value,
         uchar ***lastData, size_t **lastDataSize, ulong **lastNum, enum ProtoStage **ps, uint **tcp_seq, int *cmd)
{
    struct session *session;
    unsigned long port;
    
    port = hash_fun(laddr, raddr, lport, rport) % hash->sz;
    for (session = hash->sessions + port; session->next; session = session->next)
        if (
            session->next->raddr == raddr &&
            session->next->laddr == laddr &&
            session->next->rport == rport &&
            session->next->lport == lport
        )
        {
            *result = session->next->tv;
            *sql = session->next->sql;
            *user = session->next->user;
            *db = session->next->db;
            *value = session->next->param;

            *lastData = &(session->next->lastData);
            *lastDataSize = &(session->next->lastDataSize);
            *lastNum = &(session->next->lastNum);
            *ps = &(session->next->ps);
            *tcp_seq = &(session->next->tcp_seq);
            *cmd = session->next->cmd;

            return session->next->status;
        }
        
    return 0;
}

int
hash_get_rem(struct hash *hash,
         uint32_t laddr, uint32_t raddr, uint16_t lport, uint16_t rport)
{
    struct session *session, *next;
    unsigned long port;

    port = hash_fun(laddr, raddr, lport, rport) % hash->sz;
    for (session = hash->sessions + port; session->next; session = session->next)
        if (
            session->next->raddr == raddr &&
            session->next->laddr == laddr &&
            session->next->rport == rport &&
            session->next->lport == lport
        ) {
            // *result = session->next->tv;
            // Now remove
            next = session->next->next;
            if (session->next->sql) {
                free(session->next->sql);
                session->next->sql = NULL;
            }
            if (session->next->user) {
                free(session->next->user);
                session->next->user = NULL;
            }
            if (session->next->db) {
                free(session->next->db);
                session->next->db = NULL;
            }
            if (session->next->param) {
                free(session->next->param);
                session->next->param = NULL;
            }
            if (session->next->param_type) {
                free(session->next->param_type);
                session->next->param_type = NULL;
            }
            if (session->next->lastData) {
                free(session->next->lastData);
                session->next->lastData = NULL;
            }

            free(session->next);
            session->next = next;
            
            hash->count--;
            
            return 1;
        }
        
    return 0;
}

int
hash_set(struct hash *hash,
         uint32_t laddr, uint32_t raddr, uint16_t lport, uint16_t rport,
         struct timeval value, char *sql, int cmd, char *user, char *db, uint32_t sqlSaveLen, enum SessionStatus status)
{
    hash_load_check(hash);
    
    if (hash_set_internal(hash->sessions, hash->sz,
                             laddr, raddr, lport, rport, value, sql, cmd, user, db, sqlSaveLen, status))
    {
        hash->count++;
        return 1;
    }
        
    return 0;
                             
}

/* save stmt_id, param_count */
int 
hash_get_param_count(struct hash *hash, 
         uint32_t laddr, uint32_t raddr, uint16_t lport, uint16_t rport,
         ulong stmt_id, int *param_count, char **param_type) {

    struct session *session;
    unsigned long port;
    
    port = hash_fun(laddr, raddr, lport, rport) % hash->sz;

    ASSERT(param_count > 0);
    ASSERT(stmt_id > 0);

    for (session = hash->sessions + port; session->next; session = session->next) {
        if (
            session->next->raddr == raddr &&
            session->next->laddr == laddr &&
            session->next->rport == rport &&
            session->next->lport == lport
        ) {
            if (stmt_id == session->next->stmt_id) {
                /* is_long_data cant valid param_count in COM_EXECUTE */
                if ('1' != session->next->is_long_data) {
                    *param_count = session->next->param_count;
                    *param_type = session->next->param_type;
                } else {
                    dump(L_ERR, "this stmt_id %lu send_long_data, so cant get_param_count", stmt_id); 
                }
            } else {
                /* TODO next version support */
                dump(L_ERR, "stmt_id not same %d %d, skip it", stmt_id, session->next->stmt_id); 
                return -1;
            }
            return 0;
        }
    }
    return -1;
}

int
hash_set_is_long_data(struct hash *hash,
    uint32_t laddr, uint32_t raddr, uint16_t lport, uint16_t rport, ulong stmt_id) {
    struct session *session;
    unsigned long port;
    
    port = hash_fun(laddr, raddr, lport, rport) % hash->sz;

    for (session = hash->sessions + port; session->next; session = session->next) {
        if (
            session->next->raddr == raddr &&
            session->next->laddr == laddr &&
            session->next->rport == rport &&
            session->next->lport == lport
        ) {
            if (stmt_id == session->next->stmt_id) {
                session->next->is_long_data = '1';
                return 0;
            }
        }
    }
    return -1;
}

/* save stmt_id, param_count */
int 
hash_set_sql_len(struct hash *hash,
         uint32_t laddr, uint32_t raddr, uint16_t lport, uint16_t rport,
         uint32_t sqlSaveLen, int status) {

    struct session *session;
    unsigned long port;
    
    port = hash_fun(laddr, raddr, lport, rport) % hash->sz;

    for (session = hash->sessions + port; session->next; session = session->next) {
        if (
            session->next->raddr == raddr &&
            session->next->laddr == laddr &&
            session->next->rport == rport &&
            session->next->lport == lport
        ) {
            session->next->sqlSaveLen = sqlSaveLen; 
            // last sql change status
            if (sqlSaveLen == 0) {
                session->next->status = status;
                session->next->tcp_seq = 0;
            }
            return 0;
        }
    }
    return -1;
}
/* save stmt_id, param_count */
int 
hash_set_param_count(struct hash *hash,
         uint32_t laddr, uint32_t raddr, uint16_t lport, uint16_t rport,
         ulong stmt_id, int param_count) {

    struct session *session;
    unsigned long port;
    
    port = hash_fun(laddr, raddr, lport, rport) % hash->sz;

    ASSERT(param_count >= 0);
    ASSERT(stmt_id > 0);

    for (session = hash->sessions + port; session->next; session = session->next) {
        if (
            session->next->raddr == raddr &&
            session->next->laddr == laddr &&
            session->next->rport == rport &&
            session->next->lport == lport
        ) {
            /* TODO  only support one stmt_id */
            session->next->tcp_seq = 0;
            session->next->stmt_id = stmt_id;
            session->next->is_long_data = '\0';

            if (session->next->param_count == param_count) 
                return 0;
            else {
                if (session->next->param_type)
                    free(session->next->param_type);

                session->next->param_type = malloc(2 * param_count);
                session->next->param_count = param_count;
            }
            return 0;
        }
    }
    return -1;
}

/* save param, param_type (possible) */
int 
hash_set_param (struct hash *hash,
         uint32_t laddr, uint32_t raddr, uint16_t lport, uint16_t rport, struct timeval tv, ulong stmt_id,
          char *param, char *param_type, int param_count) {

    struct session *session;
    unsigned long port;
    
    port = hash_fun(laddr, raddr, lport, rport) % hash->sz;

    ASSERT(param > 0);

    for (session = hash->sessions + port; session->next; session = session->next) {
        if (
            session->next->raddr == raddr &&
            session->next->laddr == laddr &&
            session->next->rport == rport &&
            session->next->lport == lport
        ) {
            session->next->tcp_seq = 0;
            ASSERT(session->next->stmt_id == stmt_id);
            ASSERT(param_count >= 0);

            session->next->tv = tv;

            /* copy param_type */
            ASSERT(session->next->param_count == param_count);

            if (param_type != session->next->param_type) {
                memcpy(session->next->param_type, param_type, 2 * param_count);
            }

            ASSERT(param);
            ASSERT(strlen(param) >= 0);

            int len = 0;
            if (NULL == session->next->param) {
                len = 0; 
            } else {
                len = strlen(session->next->param); 
            }

            /* copy param */
            if (strlen(param) > len) {
                if (session->next->param)
                    free(session->next->param);
                session->next->param = malloc(strlen(param) + 1);
            }
            if (strlen(param) == 0) {
                free(session->next->param);
                session->next->param = NULL;
            } else {
                snprintf(session->next->param, strlen(param) + 1, "%s", param);
            }

            session->next->status = AfterSqlPacket;
                
            return 0;
        }
    }
    return -1;
}

static int
hash_set_internal(struct session *sessions, unsigned long sz,
         uint32_t laddr, uint32_t raddr, uint16_t lport, uint16_t rport,
         struct timeval value, char* sql, int cmd, char *user, char *db,
         uint32_t sqlSaveLen, enum SessionStatus status)
{
    struct session *session;
    unsigned long port;
    uint32_t sqlLen;
    
    port = hash_fun(laddr, raddr, lport, rport) % sz;

    for (session = sessions + port; session->next; session = session->next) {
        if (
            session->next->raddr == raddr &&
            session->next->laddr == laddr &&
            session->next->rport == rport &&
            session->next->lport == lport
        ) {
            session->next->sqlSaveLen = sqlSaveLen;
            if ((status == AfterSqlPacket) || (status == AfterPreparePacket)) {

                session->next->tcp_seq = 0;

                if (session->next->lastData) {
                    free(session->next->lastData);
                    session->next->lastData = NULL;
                }
                session->next->lastDataSize = 0;
                session->next->lastNum = 0;
                session->next->ps = 0;
            }

            if (session->next->param) {
                free(session->next->param);
                session->next->param = NULL; // after prepare then a normal sql, need remove this
            }
            /*
            if (cmd == COM_QUERY) {
                if (session->next->param_type) {
                    free(session->next->param_type);
                    session->next->param_type = NULL; // after prepare then a normal sql, need remove this
                }
                session->next->param_count = 0;
                session->next->stmt_id = 0;
            }
            */
            
            session->next->tv = value;

            if (sql != session->next->sql) {
                if (sql) {
                    if (session->next->sql) {
                        free(session->next->sql);
                        session->next->sql = NULL;
                    }
                    sqlLen = strlen(sql) ;
                    sqlLen = sqlLen > SQL_MAX_LEN ? SQL_MAX_LEN:sqlLen;
                    if (sqlLen == SQL_MAX_LEN) {
                        sql[SQL_MAX_LEN - 1] = '.'; 
                        sql[SQL_MAX_LEN - 2] = '.'; 
                        sql[SQL_MAX_LEN - 3] = '.'; 
                    }
                    session->next->sql = malloc(sqlLen + 1);
                    snprintf(session->next->sql, sqlLen + 1, "%s", sql);
                }
            }
            session->next->cmd = cmd;

            if (user != session->next->user) {
                if (user) {
                    if (session->next->user) {
                        free(session->next->user);
                        session->next->user = NULL;
                    }
                    session->next->user = malloc(strlen(user) + 1);
                    snprintf(session->next->user, strlen(user) + 1, "%s", user);
                }
            }
            if (db != session->next->db) {
                if (db) {
                    if (session->next->db) {
                        free(session->next->db);
                        session->next->db = NULL;
                    }
                    session->next->db = malloc(strlen(db) + 1);
                    snprintf(session->next->db, strlen(db) + 1, "%s", db);
                }
            }

            if (status)
                session->next->status = status;
            
            return 0;
        }
    }
    /* not in hash, new */
    session->next = malloc(sizeof(struct session));
    memset(session->next, 0, sizeof(struct session));
    if (!session->next)
        abort();
    
    session->next->raddr = raddr;
    session->next->laddr = laddr;
    session->next->rport = rport;
    session->next->lport = lport;
    
    session->next->sqlSaveLen = sqlSaveLen;

    session->next->tv = value;

    if (sql) {
        sqlLen = strlen(sql) ;
        sqlLen = sqlLen > SQL_MAX_LEN ? SQL_MAX_LEN:sqlLen;
        if (sqlLen == SQL_MAX_LEN) {
            sql[SQL_MAX_LEN - 1] = '.'; 
            sql[SQL_MAX_LEN - 2] = '.'; 
            sql[SQL_MAX_LEN - 3] = '.'; 
        }
        session->next->sql = malloc(sqlLen + 1);
        snprintf(session->next->sql, sqlLen + 1, "%s", sql);
    }
    session->next->cmd = cmd;
    
    if (user) {
        if (session->next->user) {
            free(session->next->user);
        }
        session->next->user = malloc(strlen(user) + 1);
        snprintf(session->next->user, strlen(user) + 1, "%s", user);
    }
    if (db) {
        if (session->next->db) {
            free(session->next->db);
        }
        session->next->db = malloc(strlen(db) + 1);
        snprintf(session->next->db, strlen(db) + 1, "%s", db);
    }

    if (status)
        session->next->status = status;

    session->next->next = NULL;
    
    return 1;
}

static int
hash_load_check(struct hash *hash) {
    if ((hash->count * 100) / hash->sz > MAX_LOAD_PERCENT) {
        struct session *new_sessions;
        unsigned long nsz, i, count;
        count = hash->count;
        
        // New container
        nsz = hash_newsz(hash->sz);
        
        new_sessions = malloc(nsz * sizeof(struct session));
        if (!new_sessions)
            abort();
        
        memset(new_sessions, 0, nsz * sizeof(struct session));
        
        // Rehash
        for (i = 0; i < hash->sz; i ++) {
            struct session *session;
            
            for (session = hash->sessions + i; session && session->next;
                    session = session->next)
            {
                if(session->next) {
                /* TODO not only copy below field */
                    hash_set_internal(new_sessions, nsz, session->next->laddr,
                            session->next->raddr, session->next->lport, session->next->rport,
                            session->next->tv, session->next->sql, session->next->cmd, 
                            session->next->user, session->next->db,
                            session->next->sqlSaveLen ,session->next->status);
                }
            }
        }
        //clear, here will clear count, so need save before
        hash_loop(hash, funcp_del, NULL);
        hash->count = count;
        // Switch
        hash->sz = nsz;
        free(hash->sessions);
        hash->sessions = new_sessions;
        
        return 1;

    }
    
    return 0;
}

static unsigned long
hash_fun(uint32_t laddr, uint32_t raddr, uint16_t lport, uint16_t rport) {
    unsigned long ret;
    
    ret = laddr ^ raddr;
    ret ^= (lport << 16) | rport;

    return ret;
}

static unsigned long
hash_newsz(unsigned long sz) {
    return sz * 2 + 1;
}


#ifdef _HASH_TEST_

int main() {
   
   log_init("/tmp/hash", NULL, ".log", L_OK);
    struct hash *h = hash_new();
    int i;
    struct timeval t;

    for(i = 0 ;i < 20000; i++) {
        hash_set(h, 1, 1,
            i, i, t, NULL, 0, NULL, NULL, 0, 0);
        hash_check_count(h);

        if (i % 100 == 0) 
            hash_get_rem(h, 1, 1, i, i);
    }

    hash_check_count(h);
    printf("ok - %lu %lu\n", h->count, h->sz);
    hash_clean(h);
    return 0;
}

#endif 

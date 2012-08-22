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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <string.h>

#include "stats-hash.h"
#include "log.h"

#define INITIAL_HASH_SZ     2053
#define MAX_LOAD_PERCENT    65

/* 1: receive auth packet 2: recieve ok packet start work */

struct session {
    uint32_t laddr, raddr;
    uint16_t lport, rport;
    
    struct timeval tv;

    char *sql;
    char *user;
    int cmd;
    enum SessionStatus status; 
    
    struct session *next;
    
};

struct hash {
    struct session *sessions;
    
    unsigned long sz, count;
        
};

static unsigned long
    hash_fun(uint32_t laddr, uint32_t raddr, uint16_t lport, uint16_t rport);
static int hash_set_internal(struct session *sessions, unsigned long sz,
        uint32_t laddr, uint32_t raddr, uint16_t lport, uint16_t rport,
        struct timeval tv, char *sql, int cmd, char *user, enum SessionStatus status);
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

void
hash_del(struct hash *hash) {
    free(hash->sessions);
    free(hash);
}

int
hash_get(struct hash *hash,
         uint32_t laddr, uint32_t raddr, uint16_t lport, uint16_t rport,
         struct timeval *result, char **sql, char **user)
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
            return session->next->status;
        }
        
    return 0;
}

int
hash_get_rem(struct hash *hash,
         uint32_t laddr, uint32_t raddr, uint16_t lport, uint16_t rport,
         struct timeval *result, char **sql, char **user)
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
            if (session->next->sql)
                free(session->next->sql);
            if (session->next->user)
                free(session->next->user);
            free(session->next);
            session->next = next;
            
            hash->count --;
            
            return 1;
        }
        
    return 0;
}

int
hash_set(struct hash *hash,
         uint32_t laddr, uint32_t raddr, uint16_t lport, uint16_t rport,
         struct timeval value, char *sql, int cmd, char *user, enum SessionStatus status)
{
    hash_load_check(hash);
    
    if (hash_set_internal(hash->sessions, hash->sz,
                             laddr, raddr, lport, rport, value, sql, cmd, user, status))
    {
        hash->count ++;
        return 1;
    }
        
    return 0;
                             
}

int
hash_clean(struct hash *hash, unsigned long min) {
    unsigned long i;
 
    for (i = 0; i < hash->sz; i ++) {
        struct session *session;
        
        for (session = hash->sessions + i; session->next; session = session->next)
            if (session->next->tv.tv_sec * 1000000 + session->next->tv.tv_usec <
                    min)
            {
                struct session *next;
                
                next = session->next->next;
                free(session->next);
                session->next = next;
                
                hash->count --;
                
                // This break is to prevent a segmentation fault when
                // session->next is NULL (session will be null next)
                if (!session->next)
                    break;
                
            }
            
    }
    
    return 0;
    
}

static int
hash_set_internal(struct session *sessions, unsigned long sz,
         uint32_t laddr, uint32_t raddr, uint16_t lport, uint16_t rport,
         struct timeval value, char* sql, int cmd, char *user, enum SessionStatus status)
{
    struct session *session;
    unsigned long port;
    
    port = hash_fun(laddr, raddr, lport, rport) % sz;

    for (session = sessions + port; session->next; session = session->next) {
        if (
            session->next->raddr == raddr &&
            session->next->laddr == laddr &&
            session->next->rport == rport &&
            session->next->lport == lport
        ) {
            session->next->tv = value;
            if (session->next->sql) 
                free(session->next->sql);
            session->next->sql = malloc(strlen(sql) + 1);
            snprintf(session->next->sql, strlen(sql) + 1, "%s", sql);
            session->next->cmd = cmd;

            if (user) {
                if (session->next->user) {
                    free(session->next->user);
                }
                session->next->user = malloc(strlen(user) + 1);
                snprintf(session->next->user, strlen(user) + 1, "%s", user);
            }
            if (status)
                session->next->status = status;
            
            return 0;
        }
    }
    
    session->next = malloc(sizeof(struct session));
    memset(session->next, 0, sizeof(struct session));
    if (!session->next)
        abort();
    
    session->next->raddr = raddr;
    session->next->laddr = laddr;
    session->next->rport = rport;
    session->next->lport = lport;
    
    session->next->tv = value;
    session->next->sql = malloc(strlen(sql) + 1);
    snprintf(session->next->sql, strlen(sql) + 1, "%s", sql);
    session->next->cmd = cmd;
    
    if (user) {
        if (session->next->user) {
            free(session->next->user);
        }
        session->next->user = malloc(strlen(user) + 1);
        snprintf(session->next->user, strlen(user) + 1, "%s", user);
    }

    if (status)
        session->next->status = status;

    session->next->next = NULL;
    
    return 1;
}

static int
hash_load_check(struct hash *hash) {
    if ((hash->count * 100) / hash->sz > MAX_LOAD_PERCENT) {
        struct session *new_sessions, *old_sessions;
        unsigned long nsz, i;
        
        // New container
        nsz = hash_newsz(hash->sz);
        
        new_sessions = malloc(nsz * sizeof(struct session));
        if (!new_sessions)
            abort();
        
        memset(new_sessions, 0, nsz * sizeof(struct session));
        
        // Rehash
        for (i = 0; i < hash->sz; i ++) {
            struct session *session;
            
            for (session = hash->sessions + i; session->next;
                    session = session->next)
            {
                
                hash_set_internal(new_sessions, nsz, session->laddr,
                        session->raddr, session->lport, session->rport,
                        session->tv, session->sql, session->cmd, session->user, session->status);
                        
            }
            
        }

        // Switch
        hash->sz = nsz;
        old_sessions = hash->sessions;
        hash->sessions = new_sessions;
        free(old_sessions);
        
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

int
hash_print(struct hash *hash) {
    unsigned long i;
 
    for (i = 0; i < hash->sz; i ++) {
        struct session *session;
       
        for (session = hash->sessions + i; session->next; session = session->next) {
            dump(L_OK, "[%ld][%s]%s-", i, session->next->user, session->next->sql);
        }
    }
    
    return 0;
}

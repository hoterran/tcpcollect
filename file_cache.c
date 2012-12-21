#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>

#include "log.h"
#include "utils.h"
#include "mysqlpcap.h"

#define CACHE_SIZE 100 * 1024
/* add cache max size */
#define ONE_CACHE_MAX_SIZE 4 * 1024
/* log flush time, avoid printf two much */
#define FLUSH_INTERVAL 2

typedef struct _FileCache{
    FILE *file;
    char *cache;
} FileCache;

char G_one_cache[ONE_CACHE_MAX_SIZE];

/* file or stdout */
int fileCacheInit(MysqlPcap *mp) {
    ASSERT(mp);
    FileCache *fc = mp->config = calloc(1, sizeof(FileCache));

    if (strlen(mp->cacheFileName) > 0) {
        fc->file = fopen(mp->cacheFileName, "a+");
        if (NULL == fc->file) {
            dump(L_ERR, "%s can open", mp->cacheFileName); 
        }
    }

    if (NULL == fc->file) fc->file = stdout;

    fc->cache = calloc(1, CACHE_SIZE);
    setbuffer(fc->file, fc->cache, CACHE_SIZE);
    mp->cacheFlushTime = time(NULL);
    return OK;
}

void fileCacheAdd(MysqlPcap *mp, const char *fmt, ...) {
    ASSERT(mp);
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(G_one_cache, sizeof(G_one_cache), fmt, ap); 
    va_end(ap);

    FileCache *fc = mp->config;
    fprintf(fc->file, "%s", G_one_cache);
}

void fileCacheFlush(MysqlPcap* mp, int force) {
    ASSERT(mp && mp->config);
    FileCache *fc = mp->config;
    ASSERT(mp->fakeNow >= mp->cacheFlushTime);

    /* not force flush and not on time would return */
    if ((force == 0) && (mp->fakeNow - mp->cacheFlushTime <= FLUSH_INTERVAL)) {
        return;
    }
    fflush(fc->file);
    mp->cacheFlushTime = mp->fakeNow;
}


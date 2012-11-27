#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <stdarg.h>
#include <syslog.h>
#include <string.h>
#include <signal.h>

#include "log.h"

#define LOG_MAX_LEN 4096
#define LOG_FILE_LEN 128
#define PREFIX_LEN 32

typedef struct _Log_t {
    int level;
    char syslog_enabled;
    char *filename;
    char *prefix;       /* mysqlpcap*/
    char *suffix;       /* .log */
    char *format;       /* %Y-%m-%d | NULL */
    char *old_time_format; /* is need change filename ?*/
    char *new_time_format; /* malloc first, so cant need malloc */
} Log;

Log G_log;

/* G_log.format is not NULL, will go to this function */
void log_change_filename(time_t t) {

    struct tm now;

    localtime_r(&t, &now);
    strftime(G_log.new_time_format, PREFIX_LEN, G_log.format, &now);

    if (0 == strlen(G_log.old_time_format)) {
        /* first call by log_init */
        snprintf(G_log.old_time_format, PREFIX_LEN, "%s", G_log.new_time_format);
        snprintf(G_log.filename, LOG_FILE_LEN, "%s%s%s", 
            G_log.prefix, G_log.old_time_format, G_log.suffix);
    } else {
        /* call by log */ 
        if (0 != strcmp(G_log.old_time_format, G_log.new_time_format)) {
            snprintf(G_log.old_time_format, PREFIX_LEN, "%s", G_log.new_time_format);
            snprintf(G_log.filename, LOG_FILE_LEN, "%s%s%s", 
                G_log.prefix, G_log.old_time_format, G_log.suffix);
        }
    }
}

/* 
 * format time_t datetime format, when logging will conclude is changed?, so write new log file
 *
 */

/* use signal change level */
void log_change_level() {
    if (G_log.level == L_OK)
        G_log.level = L_DEBUG;
    else 
        G_log.level = L_OK;

    dump(L_OK, "log level change to %d", G_log.level);
}

void 
log_init(const char *prefix, const char *format, const char *suffix) {

    if (prefix == NULL) {
        G_log.level = L_OK;
        return;
    }

    struct sigaction act;
    act.sa_handler = log_change_level;
    act.sa_flags = SA_RESTART;
    sigemptyset(&act.sa_mask);
    sigaddset(&act.sa_mask, SIGUSR1);
    sigaction(SIGUSR1, &act, NULL);

    G_log.level = L_DEBUG;
    G_log.syslog_enabled = 0;

    G_log.filename = malloc(LOG_FILE_LEN);
    G_log.prefix = malloc(PREFIX_LEN);
    G_log.suffix = malloc(PREFIX_LEN);
    G_log.filename = malloc(LOG_FILE_LEN);
    G_log.old_time_format = malloc(PREFIX_LEN);
    G_log.new_time_format = malloc(PREFIX_LEN);
    memset(G_log.new_time_format, 0, PREFIX_LEN);

    snprintf(G_log.prefix, PREFIX_LEN, "%s", prefix);
    snprintf(G_log.suffix, PREFIX_LEN, "%s", suffix);

    if (format) {
        G_log.format = malloc(PREFIX_LEN);
        snprintf(G_log.format, PREFIX_LEN, "%s", format);
        log_change_filename(time(NULL));
    } else {
        G_log.format = NULL;
        snprintf(G_log.filename, LOG_FILE_LEN, "%s%s", 
            G_log.prefix, G_log.suffix);
    }
}

void 
_log(const char *levelstring, int level, 
    const char *fmt, ...) {

    const int syslogLevelMap[] = { L_DEBUG, L_INFO, L_OK, L_WARN, L_ERR };
    time_t now = time(NULL);
    va_list ap;
    FILE *fp; 
    char buf[64];
    char msg[LOG_MAX_LEN];
  
    if (level > G_log.level) return;
  
    if (G_log.format) log_change_filename(now);

    fp = (G_log.filename == NULL) ? stdout : fopen(G_log.filename, "a");
    if (!fp) return;
  
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap); 
    va_end(ap);
  
    strftime(buf,sizeof(buf),"%m-%d %H:%M:%S" ,localtime(&now));
    fprintf(fp,"[%d][%s] %s - %s\n",(int)getpid(),
        levelstring, buf, msg);
    fflush(fp);

    if (G_log.filename && (level <= L_OK)) 
        printf("%s\n", msg);
  
    if (G_log.filename) fclose(fp);
  
    if (G_log.syslog_enabled) syslog(syslogLevelMap[level], "%s", msg);
} 

#ifdef _LOG_TEST_

int 
main(int argc, char *argv[]) {

    /* 0 stdout */
    log_init(NULL, NULL, ".log");

    dump(L_ERR, "ERR");
    dump(L_INFO, "INFO");
    dump(L_WARN, "WARN");
    dump(L_OK, "OK");
    dump(L_DEBUG, "DEBUG");
    sigusr1_handler();              // haha
    dump(L_DEBUG, "DEBUG");

    /* 1 */
    log_init("/tmp/test", NULL, ".log");

    dump(L_ERR, "ERR");
    dump(L_INFO, "INFO");
    dump(L_WARN, "WARN");
    dump(L_OK, "OK");
    dump(L_DEBUG, "DEBUG");
    sigusr1_handler();              // haha
    dump(L_DEBUG, "DEBUG");

    /* 2 */
    log_init("/tmp/test-","%Y-%m-%d-%H-%M", ".log");

    dump(L_ERR, "ERR");
    dump(L_INFO, "INFO");
    dump(L_WARN, "WARN");
    dump(L_OK, "OK");
    dump(L_DEBUG, "DEBUG");
    sigusr1_handler();              // haha
    dump(L_DEBUG, "DEBUG");

    while(1) {
        dump(L_ERR, "ERR");
        dump(L_INFO, "INFO");
        dump(L_WARN, "WARN");
        dump(L_OK, "OK");
        dump(L_DEBUG, "DEBUG");
        sigusr1_handler();              // haha
        dump(L_DEBUG, "DEBUG");
        sleep(10);
    }
}

#endif

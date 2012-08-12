#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <time.h>
#include <stdarg.h>

void
alog (int level, char *fmt, ...)
{
    char levelStr[][32] = {"ERROR", "WARN", "INFO"};
    char head[128], body[10240],logname[128];
    struct tm tm;
    time_t t;
    va_list ap;
    FILE *fp;

    time(&t);
    localtime_r(&t, &tm);

    snprintf(head, sizeof(head),"%d:%02d:%02d %s", 
        tm.tm_hour, tm.tm_min, tm.tm_sec, levelStr[level]);
    va_start(ap, fmt);
    vsnprintf(body, sizeof(body), fmt, ap);
    va_end(ap);

    snprintf(logname, sizeof(logname), "/tmp/webdump-agent%d-%02d-%02d.log",
        1900+tm.tm_year, tm.tm_mon+1, tm.tm_mday);
    fp = fopen(logname, "a+");
    if (NULL == fp) {
        printf("[%s] %s\n\n", head, body);
    } else {
        fprintf(fp, "[%s] %s\n\n", head, body);
        fclose(fp);
    }

    return;
}

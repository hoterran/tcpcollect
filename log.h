

/*
 syslog.h

 54 #define LOG_ERR     3    error conditions 
 55 #define LOG_WARNING 4    warning conditions 
 56 #define LOG_NOTICE  5    normal but significant condition, success
 57 #define LOG_INFO    6    informational 
 58 #define LOG_DEBUG   7    debug-level messages 

*/

#define L_ERR   3
#define L_WARN  4 
#define L_OK    5 
#define L_INFO  6
#define L_DEBUG 7 

#define dump(x,y...)    _log(#x, x, ##y)

void 
log_init(const char *prefix, const char *format, const char *suffix);

void 
_log(const char *levelstring, int level, const char *fmt, ...);

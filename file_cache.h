
int fileCacheInit(MysqlPcap *mp);

int fileCacheAdd(MysqlPcap *mp, const char *fmt, ...);

int fileCacheFlush(MysqlPcap* mp, int force);

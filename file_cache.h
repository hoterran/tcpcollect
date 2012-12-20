
int fileCacheInit(MysqlPcap *mp);

void fileCacheAdd(MysqlPcap *mp, const char *fmt, ...);

void fileCacheFlush(MysqlPcap* mp, int force);

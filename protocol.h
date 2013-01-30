#ifndef _PROTOCOL_H_
#define _PROTOCOL_H_

enum enum_server_command {  
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

enum enum_field_types { 
    MYSQL_TYPE_DECIMAL, MYSQL_TYPE_TINY,
    MYSQL_TYPE_SHORT,  MYSQL_TYPE_LONG,
    MYSQL_TYPE_FLOAT,  MYSQL_TYPE_DOUBLE,
    MYSQL_TYPE_NULL,   MYSQL_TYPE_TIMESTAMP,
    MYSQL_TYPE_LONGLONG,MYSQL_TYPE_INT24,
    MYSQL_TYPE_DATE,   MYSQL_TYPE_TIME,
    MYSQL_TYPE_DATETIME, MYSQL_TYPE_YEAR,
    MYSQL_TYPE_NEWDATE, MYSQL_TYPE_VARCHAR,
    MYSQL_TYPE_BIT,
    MYSQL_TYPE_NEWDECIMAL=246,
    MYSQL_TYPE_ENUM=247,
    MYSQL_TYPE_SET=248,
    MYSQL_TYPE_TINY_BLOB=249,
    MYSQL_TYPE_MEDIUM_BLOB=250,
    MYSQL_TYPE_LONG_BLOB=251,
    MYSQL_TYPE_BLOB=252,
    MYSQL_TYPE_VAR_STRING=253,
    MYSQL_TYPE_STRING=254,
    MYSQL_TYPE_GEOMETRY=255
};

enum ProtoStage {
    FIELD_STAGE = '1',
    EOF_STAGE = '2',
    RESULT_STAGE = '3'
};

int isCompressPacket(char *payload, uint32 payload_len, int status);

int is_sql (char *payload, uint32 payload_len, char **user, char **db, uint32 sqlSaveLen);

int parse_sql(char *payload, uint32 payload_len, char **sql, uint32 sqlSaveLen);

long parse_result(char *payload, uint32 payload_len, 
    uchar **myLastData, size_t *myLastDataSize, ulong *myLastNum, enum ProtoStage *ps);

char* parse_param(char *payload, uint32 payload_len, int param_count, 
    char *param_type, char *param, size_t param_len);

int parse_stmt_id(char *payload, uint32 payload_len, ulong *stmt_id);

int parse_prepare_ok(char *payload, uint32 payload_len, ulong *stmt_id, 
    int *param_count);

#define uint2korr(A)    (uint16) (((uint16) ((uchar) (A)[0])) +\
    ((uint16) ((uchar) (A)[1]) << 8))

#define uint3korr(A)    (uint32) (((uint32) ((uchar) (A)[0])) +\
    (((uint32) ((uchar) (A)[1])) << 8) +\
    (((uint32) ((uchar) (A)[2])) << 16))

#define uint4korr(A)    (uint32) (((uint32) ((uchar) (A)[0])) +\
    (((uint32) ((uchar) (A)[1])) << 8) +\
    (((uint32) ((uchar) (A)[2])) << 16) +\
    (((uint32) ((uchar) (A)[3])) << 24))

#define uint8korr(A)    ((ulonglong)(((uint32) ((uchar) (A)[0])) +\
    (((uint32) ((uchar) (A)[1])) << 8) +\
    (((uint32) ((uchar) (A)[2])) << 16) +\
    (((uint32) ((uchar) (A)[3])) << 24)) +\
    (((ulonglong) (((uint32) ((uchar) (A)[4])) +\
    (((uint32) ((uchar) (A)[5])) << 8) +\
    (((uint32) ((uchar) (A)[6])) << 16) +\
    (((uint32) ((uchar) (A)[7])) << 24))) <<\
    32))

#define int2store(T,A)       do { uint def_temp= (uint) (A) ;\
                                  *((uchar*) (T))=  (uchar)(def_temp); \
                                   *((uchar*) (T)+1)=(uchar)((def_temp >> 8)); \
                             } while(0)

#define int4store(T,A)       do { *((char *)(T))=(char) ((A));\
                                  *(((char *)(T))+1)=(char) (((A) >> 8));\
                                  *(((char *)(T))+2)=(char) (((A) >> 16));\
                                  *(((char *)(T))+3)=(char) (((A) >> 24)); } while(0)

#define int8store(T,A) do { uint def_temp= (uint) (A), def_temp2= (uint) ((A) >> 32); \
    int4store((T),def_temp); \
    int4store((T+4),def_temp2); } while(0)

#define memcpy_fixed(A,B,C) memcpy((A),(B),(C))

#define float4store(V,M) memcpy_fixed((uchar*) V,(uchar*) (&M),sizeof(float))

#define float8store(T,V) do { *(T)= ((uchar *) &V)[7];\
                              *((T)+1)=(char) ((uchar *) &V)[6];\
                              *((T)+2)=(char) ((uchar *) &V)[5];\
                              *((T)+3)=(char) ((uchar *) &V)[4];\
                              *((T)+4)=(char) ((uchar *) &V)[3];\
                              *((T)+5)=(char) ((uchar *) &V)[2];\
                              *((T)+6)=(char) ((uchar *) &V)[1];\
                              *((T)+7)=(char) ((uchar *) &V)[0]; } while(0)

#endif

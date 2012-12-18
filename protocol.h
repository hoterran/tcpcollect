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

int is_sql (char *payload, uint32 payload_len, char **user, uint32 sqlSaveLen);

int parse_sql(char *payload, uint32 payload_len, char **sql, uint32 sqlSaveLen);

ulong parse_result(char *payload, uint32 payload_len, 
    uchar **myLastData, size_t *myLastDataSize, ulong *myLastNum, enum ProtoStage *ps);

char* parse_param(char *payload, uint32 payload_len, int param_count, 
    char *param_type, char *param, size_t param_len);

int parse_stmt_id(char *payload, uint32 payload_len, int *stmt_id);

int parse_prepare_ok(char *payload, uint32 payload_len, int *stmt_id, 
    int *param_count);

int parse_stmt_id(char *payload, uint32 payload_len, int *stmt_id);

#endif

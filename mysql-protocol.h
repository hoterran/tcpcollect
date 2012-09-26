
enum enum_field_types { MYSQL_TYPE_DECIMAL, MYSQL_TYPE_TINY,
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


int is_sql (char *payload, int payload_len, char **user);

int parse_sql(char *payload, char** sql, int payload_len);

ulong parse_result(char* payload, int payload_len, 
    uchar** myLastData, size_t *myLastDataSize, ulong *myLastNum);

int parse_param(char *payload, int payload_len, int param_count, 
    char **param_type, char *param);

int parse_stmt_id(char *payload, int payload_len, int *stmt_id);

int parse_prepare_ok(char *payload, int payload_len, int *stmt_id, 
    short *param_count);

int parse_stmt_id(char *payload, int payload_len, int *stmt_id);


#include <stdio.h>
#include <mysql.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "c.h"
#define STRING_SIZE 1024

/*

MYSQL_TYPE_TIMESTAMP    TIMESTAMP field
MYSQL_TYPE_DATE         DATE field
MYSQL_TYPE_TIME         TIME field
MYSQL_TYPE_DATETIME     DATETIME field

*/

#define DROP_SAMPLE_TABLE "DROP TABLE IF EXISTS test_table"
#define CREATE_SAMPLE_TABLE "CREATE TABLE test_table(col1 INT, col2 varchar(40))"
#define INSERT_SAMPLE "INSERT INTO test_table(col1,col2) VALUES(?,?)"

int main (int argc, char *argv[]) {

    MYSQL *mysql;
    MYSQL_RES *result;
    MYSQL_ROW row;
    my_bool reconnect = 0;
    mysql = mysql_init(NULL);
    mysql_options(mysql, MYSQL_OPT_RECONNECT, &reconnect);

    CONN(0);

    MYSQL_STMT    *stmt;
    MYSQL_BIND    bind[2];
    my_ulonglong  affected_rows;
    int           param_count;
    short         small_data;
    int           int_data;
    char          str_data[STRING_SIZE];
    unsigned long str_length;
    my_bool       is_null;

    mysql_query(mysql, DROP_SAMPLE_TABLE);

    mysql_query(mysql, CREATE_SAMPLE_TABLE);

    stmt = mysql_stmt_init(mysql);

    mysql_query(mysql, "select 1 from test_table"); // -------------------1  ok
    result = mysql_store_result(mysql);
    while(mysql_fetch_row(result));
    mysql_free_result(result);

    mysql_stmt_prepare(stmt, INSERT_SAMPLE, strlen(INSERT_SAMPLE));
    memset(bind, 0, sizeof(bind));
    bind[0].buffer_type= MYSQL_TYPE_LONGLONG;
    bind[0].buffer= (char *)&int_data;
    bind[0].is_null= 0;
    bind[1].buffer_type= MYSQL_TYPE_STRING;
    bind[1].buffer= (char *)str_data;
    bind[1].is_null= 0;
    bind[1].length= &str_length;        //实际大小, bind_
    mysql_stmt_bind_param(stmt, bind);

    int_data= 2;             /* integer */
    strncpy(str_data, "MySQL", STRING_SIZE); /* string  */
    str_length= strlen(str_data);

    mysql_stmt_execute(stmt);               // --------------------------2  ok

    mysql_query(mysql, "select 3 from test_table"); // -------------------3
    result = mysql_store_result(mysql);
    while(mysql_fetch_row(result));
    mysql_free_result(result);

    mysql_query(mysql, "select 4 from test_table"); // --------------------4
    result = mysql_store_result(mysql);
    while(mysql_fetch_row(result));
    mysql_free_result(result);

    int_data= 5;             /* integer */
    strncpy(str_data, "MySQL11111111", STRING_SIZE); /* string  */
    str_length= strlen(str_data);

    mysql_stmt_execute(stmt); //  failure for prepare sql cover by  normal sql

    mysql_stmt_prepare(stmt, INSERT_SAMPLE, strlen(INSERT_SAMPLE));
    memset(bind, 0, sizeof(bind));
    bind[0].buffer_type= MYSQL_TYPE_LONGLONG;
    bind[0].buffer= (char *)&int_data;
    bind[0].is_null= 0;
    bind[1].buffer_type= MYSQL_TYPE_STRING;
    bind[1].buffer= (char *)str_data;
    bind[1].is_null= 0;
    bind[1].length= &str_length;        //实际大小, bind_
    mysql_stmt_bind_param(stmt, bind);

    int_data= 6;             /* integer */
    strncpy(str_data, "MySQL11111111", STRING_SIZE); /* string  */
    str_length= strlen(str_data);

    mysql_stmt_execute(stmt); //  success

    mysql_query(mysql, "select 7 from test_table"); // success

    int_data= 8;        
    mysql_stmt_execute(stmt); //failure 

    mysql_stmt_close(stmt);
}

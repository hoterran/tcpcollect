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

    char *sql = "select * from test_table";

    mysql_stmt_prepare(stmt, sql, strlen(sql));

    mysql_stmt_execute(stmt);               // --------------------------2  ok
    
    while(!mysql_stmt_fetch(stmt)) { // here return resultset
        printf("%d - %s\n", int_data, str_data); 
    }

    mysql_stmt_close(stmt);
}

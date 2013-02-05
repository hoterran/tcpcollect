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

    mysql_query(mysql, "select * from test_table");
    
    result = mysql_store_result(mysql);

    while(mysql_fetch_row(result));

    mysql_free_result(result);

}

#include <stdio.h>
#include <mysql.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#define STRING_SIZE 1024

#define DROP_SAMPLE_TABLE "DROP TABLE IF EXISTS test_table"
#define CREATE_SAMPLE_TABLE "CREATE TABLE test_table(col1 INT, col2 VARCHAR(40))"
#define INSERT_SAMPLE "INSERT INTO test_table(col1,col2) VALUES(1, \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\")"

#define INSERT_SAMPLE2 "INSERT INTO test_table select * from test_table"

int main (int argc, char *argv[]) {

    MYSQL *mysql;
    MYSQL_RES *result;
    MYSQL_ROW row;
    my_bool reconnect = 0;
    mysql = mysql_init(NULL);
    mysql_options(mysql, MYSQL_OPT_RECONNECT, &reconnect);
 
    mysql_real_connect(mysql, "127.0.0.1", "root", "root", "test", 3306, NULL, 0);

    MYSQL_STMT    *stmt;
    MYSQL_BIND    bind[7];
    my_ulonglong  affected_rows;
    int           param_count;
    short         small_data;
    int           int_data;
    char          str_data[STRING_SIZE];
    unsigned long str_length;
    my_bool       is_null;

    mysql_query(mysql, "select * from d limit 100000");

    result = mysql_store_result(mysql);

    while(mysql_fetch_row(result));

    mysql_close(mysql);
}

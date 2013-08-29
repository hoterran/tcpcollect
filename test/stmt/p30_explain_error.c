#include <stdio.h>
#include <mysql.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include "c.h"
#define STRING_SIZE 1024

#define SQL "explain select aaaa"

int main (int argc, char *argv[]) {

    MYSQL *mysql;
    MYSQL_RES *result;
    MYSQL_ROW row;
    my_bool reconnect = 0;
    mysql = mysql_init(NULL);
    mysql_options(mysql, MYSQL_OPT_RECONNECT, &reconnect);
 
    CONN(0);

    MYSQL_STMT    *stmt;
    MYSQL_BIND    bind[7];
    my_ulonglong  affected_rows;
    int           param_count;
    short         small_data;
    int           int_data;
    char          str_data[STRING_SIZE];
    unsigned long str_length;
    my_bool       is_null;

    int id = mysql_query(mysql, SQL);

    result = mysql_store_result(mysql);

    printf("%d %d\n", id, mysql_errno(mysql));

    if (result)
        while(mysql_fetch_row(result)) {
            printf("ok\n");
        }

    mysql_close(mysql);
}

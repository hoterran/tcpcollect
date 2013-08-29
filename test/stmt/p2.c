#include <stdio.h>
#include <mysql.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "c.h"
#define INSERT_SQL "insert into player_copy(id, name) values(?, ?)"

void main(int argc, char **argv)
{
    MYSQL *mysql,*sock;
    MYSQL_STMT *st;
    MYSQL_BIND bind[2];

    int param_count;
    int int_data;
    int i;
    char str_data[3];
    unsigned long str_length;
    my_bool is_null;

    mysql = mysql_init(NULL);
    if (!(sock = CONN(0))) {
        fprintf(stderr, "Couldn't connect to engine!\n%s\n\n", mysql_error(mysql));
        perror("");
        exit(1);
    }

    mysql_query(sock, "create table player_copy (id int, name varchar(20))");

    st = mysql_stmt_init(mysql);
    mysql_stmt_prepare(st, INSERT_SQL, 47);
    param_count = mysql_stmt_param_count(st);
    fprintf(stdout, " total parameters in INSERT: %d\n", param_count);

    for (i = 1; i < 1000; i ++) {
        int_data = i;
        str_data[0] = 'a';
        str_data[1] = 'b';
        str_data[2] = 'c';
        str_length = 3;
        is_null = 0;

        bind[0].buffer_type= MYSQL_TYPE_LONG;
        bind[0].buffer= &int_data;
        bind[0].is_null= &is_null;

        bind[1].buffer_type= MYSQL_TYPE_VAR_STRING;
        bind[1].buffer= (char *)str_data;
        bind[1].is_null= &is_null;
        bind[1].length= &str_length;

        mysql_stmt_bind_param(st, bind);
        mysql_stmt_execute(st);
    }

    mysql_query(sock, "drop table player_copy");
}

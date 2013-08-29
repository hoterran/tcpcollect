#include <stdio.h>
#include <mysql.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "c.h"

#define SQL "select user(), current_user()"

void main(int argc, char **argv)
{
    MYSQL *mysql,*sock;
    MYSQL_STMT *st;
    char       str[2][50];
    MYSQL_BIND my_bind[2];

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

    st = mysql_stmt_init(mysql);
    mysql_stmt_prepare(st, SQL, strlen(SQL));
    param_count = mysql_stmt_param_count(st);

  bzero((char*) my_bind, sizeof(MYSQL_BIND));
    my_bind[0].buffer_type= MYSQL_TYPE_STRING;
      my_bind[0].buffer= (void *)str[0];
        my_bind[0].buffer_length= sizeof(str[0]);
          my_bind[1]= my_bind[0];
            my_bind[1].buffer= (void *)str[1];

    mysql_stmt_bind_param(st, my_bind);
    mysql_stmt_execute(st);

    while (mysql_stmt_fetch(st) != MYSQL_NO_DATA);
}

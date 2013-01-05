#include <stdio.h>
#include <mysql.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "c.h"

int main(int argc, char* argv[])
{
    MYSQL *mysql,*sock;
    MYSQL_ROW row;
    MYSQL_RES *result;

    mysql = mysql_init(NULL);

    if (!(sock = CONN(0))) {
        fprintf(stderr, "Couldn't connect to engine!\n%s\n\n", mysql_error(mysql));
        perror("");
        exit(1);
    }

    char *sql;

    int i;

    for(i = 0; i < 100000; i++) {

        mysql_select_db(sock, "test");
/*
        sql = "use test";

        mysql_query(sock, sql);
        sql = "use mysql";

        mysql_query(sock, sql);
*/

        mysql_select_db(sock, "mysql");
    }

    mysql_close(mysql);

    return 0;
}

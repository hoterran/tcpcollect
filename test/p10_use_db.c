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

    for(i = 0; i < 10000; i++) {
        //1
        mysql_select_db(sock, "mysql");

        //2 
        sql = "use test";
        mysql_query(sock, sql);

        mysql_query(sock, "select * from n");

        result = mysql_store_result(sock);

        mysql_free_result(result);

        //3
        mysql_select_db(sock, "information_schema");
    }

    mysql_close(mysql);

    return 0;
}

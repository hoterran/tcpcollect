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

    /* add compress */
    mysql = mysql_init(NULL);
    if (!(sock = CONN(CLIENT_COMPRESS))) {
        fprintf(stderr, "Couldn't connect to engine!\n%s\n\n", mysql_error(mysql));
        perror("");
        exit(1);
    }

    char *sql = "select 1";

    mysql_query(sock, sql);
    result= mysql_store_result(sock)
    row = mysql_fetch_row(result);

    return 0;
}


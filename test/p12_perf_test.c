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

    int i;
  
    char *sql = "select 111111111111111111111111111111111111111111111111111111111111111111111111111";

    while(1) {
        mysql_query(sock, sql);
        result = mysql_store_result(sock);
        mysql_free_result(result);
    }

    mysql_close(mysql);

    return 0;
}

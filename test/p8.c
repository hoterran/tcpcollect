#include <stdio.h>
#include <mysql.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char* argv[])
{
    MYSQL mysql,*sock;
    MYSQL_ROW row;
    MYSQL_RES *result;

    mysql_init(&mysql);
    if (!(sock = mysql_real_connect(&mysql, "127.0.0.1", "root", "root", "test", 3306, NULL, CLIENT_MULTI_STATEMENTS))) {
        fprintf(stderr, "Couldn't connect to engine!\n%s\n\n", mysql_error(&mysql));
        perror("");
        exit(1);
    }

    char *sql = "select 1;select * from n";

     mysql_query(sock, sql);
    do
    {
        printf("total affected rows: %lld\n", mysql_affected_rows(sock));
        if (!(result= mysql_store_result(sock)))
        {
            printf("Got fatal error processing query\n");
            exit(1);
        }
        row = mysql_fetch_row(result);
        printf("%s\n", row[0]);
        mysql_free_result(result);
    } while (!mysql_next_result(sock));

    return 0;
}


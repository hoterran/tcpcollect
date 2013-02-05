#include <stdio.h>
#include <mysql.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "c.h"

void main(int argc, char **argv)
{
    MYSQL *mysql,*sock;
    MYSQL_STMT *st;
    int        rc;
    char       *sql;
    int        nData= 1;
    char       tData= 1;
    short      sData= 10;
    long        bData= 20;
    MYSQL_BIND my_bind[1];

    mysql = mysql_init(NULL);
    if (!(sock = CONN(0))) {
        fprintf(stderr, "Couldn't connect to engine!\n%s\n\n", mysql_error(mysql));
        perror("");
        exit(1);
    }

    rc= mysql_query(sock, "DROP TABLE IF EXISTS a1");

    sql= (char *)"CREATE TABLE a1(c1 int)";

    rc= mysql_query(sock, sql);

    /* insert by prepare - all integers */
    char *query = (char *)"INSERT INTO a1(c1) VALUES(?)";
    st = mysql_stmt_init(mysql);
    mysql_stmt_prepare(st, query, strlen(query));

  /* Always bzero all members of bind parameter */
    bzero((char*) my_bind, sizeof(my_bind));

    /*tinyint*/
    my_bind[0].buffer_type= MYSQL_TYPE_LONG;
    my_bind[0].buffer= (void *)&nData;

    rc= mysql_stmt_bind_param(st, my_bind);

    rc= mysql_stmt_execute(st);

    mysql_stmt_close(st);

    mysql_close(sock);
}

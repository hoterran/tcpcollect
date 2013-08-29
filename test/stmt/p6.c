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
    int        rc;
    char       *sql;
    int        nData= 1;
    char       tData= 1;
    short      sData= 10;
    long        bData= 20;
    MYSQL_BIND my_bind[6];

    mysql = mysql_init(NULL);
    if (!(sock = CONN(0))) {
        fprintf(stderr, "Couldn't connect to engine!\n%s\n\n", mysql_error(mysql));
        perror("");
        exit(1);
    }

    rc= mysql_query(sock, "DROP TABLE IF EXISTS test_prepare_ext");

    sql= (char *)"CREATE TABLE test_prepare_ext"
               "("
               " c1  tinyint,"
               " c2  smallint,"
               " c3  mediumint,"
               " c4  int,"
               " c5  integer,"
               " c6  bigint,"
               " c7  float,"
               " c8  double,"
               " c9  double precision,"
               " c10 real,"
               " c11 decimal(7, 4),"
               " c12 numeric(8, 4),"
               " c13 date,"
               " c14 datetime,"
               " c15 timestamp(14),"
               " c16 time,"
               " c17 year,"
               " c18 bit,"
               " c19 bool,"
               " c20 char,"
               " c21 char(10),"
               " c22 varchar(30),"
               " c23 tinyblob,"
               " c24 tinytext,"
               " c25 blob,"
               " c26 text,"
               " c27 mediumblob,"
               " c28 mediumtext,"
               " c29 longblob,"
               " c30 longtext,"
               " c31 enum('one', 'two', 'three'),"
               " c32 set('monday', 'tuesday', 'wednesday'))";

    rc= mysql_query(sock, sql);

    /* insert by prepare - all integers */
    char *query = (char *)"INSERT INTO test_prepare_ext(c1, c2, c3, c4, c5, c6) VALUES(?, ?, ?, ?, ?, ?)";
    st = mysql_stmt_init(mysql);
    mysql_stmt_prepare(st, query, strlen(query));

  /* Always bzero all members of bind parameter */
    bzero((char*) my_bind, sizeof(my_bind));

    /*tinyint*/
    my_bind[0].buffer_type= MYSQL_TYPE_TINY;
    my_bind[0].buffer= (void *)&tData;

    /*smallint*/
    my_bind[1].buffer_type= MYSQL_TYPE_SHORT;
    my_bind[1].buffer= (void *)&sData;

    /*mediumint*/
    my_bind[2].buffer_type= MYSQL_TYPE_LONG;
    my_bind[2].buffer= (void *)&nData;

    /*int*/
    my_bind[3].buffer_type= MYSQL_TYPE_LONG;
    my_bind[3].buffer= (void *)&nData;

    /*integer*/
    my_bind[4].buffer_type= MYSQL_TYPE_LONG;
    my_bind[4].buffer= (void *)&nData;

    /*bigint*/
    my_bind[5].buffer_type= MYSQL_TYPE_LONGLONG;
    my_bind[5].buffer= (void *)&bData;

    rc= mysql_stmt_bind_param(st, my_bind);

    for (nData= 0; nData<10; nData++, tData++, sData++, bData++)
    {
        rc= mysql_stmt_execute(st);
    }

  /* now fetch the results ..*/

    query = "SELECT c1, c2, c3, c4, c5, c6 FROM test_prepare_ext";
    mysql_stmt_prepare(st, query, strlen(query));

    /* get the result */
    rc= mysql_stmt_execute(st);

    mysql_stmt_close(st);

    mysql_close(sock);
}

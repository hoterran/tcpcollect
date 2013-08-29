#include <stdio.h>
#include <mysql.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "c.h"
#define STRING_SIZE 1024

/*
MYSQL_TYPE_TIMESTAMP    TIMESTAMP field
MYSQL_TYPE_DATE         DATE field
MYSQL_TYPE_TIME         TIME field
MYSQL_TYPE_DATETIME     DATETIME field
*/

//#define DROP_SAMPLE_TABLE "DROP TABLE IF EXISTS test_table"
//#define CREATE_SAMPLE_TABLE "CREATE TABLE test_table(col1 INT, col2 int, col21 varchar(40), col22 varchar(40), col3 SMALLINT, col4 TIMESTAMP, col5 datetime, col6 date, col7 time)"
//#define INSERT_SAMPLE "INSERT INTO test_table(col1,col2,col3, col4, col5, col6, col7, col21, col22) VALUES(1,2,1,1,1,1,1,1,1)"

int main (int argc, char *argv[]) {

    MYSQL *mysql;
    MYSQL_RES *result;
    MYSQL_ROW row;
    my_bool reconnect = 0;
    mysql = mysql_init(NULL);
    mysql_options(mysql, MYSQL_OPT_RECONNECT, &reconnect);

    CONN(0);

    MYSQL_STMT    *stmt;
    MYSQL_BIND    bind[1];
    MYSQL_BIND    bResult[1];
    unsigned long length[1];
    my_ulonglong  affected_rows;
    int           param_count;
    short         small_data;
    long long           int_data;
    char          str_data[STRING_SIZE];
    unsigned long str_length;
    my_bool       is_null[1];

    is_null[0] = 0;
    stmt = mysql_stmt_init(mysql);
    if (!stmt)
    {
      fprintf(stderr, " mysql_stmt_init(), out of memory\n");
      exit(0);
    }

    #define SELECT_EXAMPLE "select id from SMALL111 where id > ?"

    if (mysql_stmt_prepare(stmt, SELECT_EXAMPLE, strlen(SELECT_EXAMPLE)))
    {
      fprintf(stderr, " mysql_stmt_prepare(), INSERT failed\n");
      fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
      exit(0);
    }
    fprintf(stdout, " prepare, INSERT successful\n");

    /* Bind the data for all 3 parameters */

    memset(bind, 0, sizeof(bind));

    bind[0].buffer_type= MYSQL_TYPE_LONGLONG;
    bind[0].buffer= (char *)&int_data;
    bind[0].is_null= &is_null[0];
    bind[0].length = &length[0];

    /* Bind the buffers */
    if (mysql_stmt_bind_param(stmt, bind))
    {
      fprintf(stderr, " mysql_stmt_bind_param() failed\n");
      fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
      exit(0);
    }

    int_data= 0x0000000000000001;        

    if (mysql_stmt_execute(stmt))
    {
      fprintf(stderr, " mysql_stmt_execute(), 1 failed\n");
      fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
      exit(0);
    }

    memset(bResult, 0, sizeof(bResult));
    bResult[0].buffer_type= MYSQL_TYPE_LONGLONG;
    bResult[0].buffer= (char *)&int_data;
    bResult[0].is_null= &is_null[0];
    bResult[0].length= &length[0];

    mysql_stmt_bind_result(stmt, bResult);
    mysql_stmt_store_result(stmt); 

    while(!mysql_stmt_fetch(stmt)) {
        printf("%c-%lld\n", is_null[0], int_data);
    }

    mysql_stmt_reset(stmt);
    mysql_stmt_close(stmt);
    sleep(3);
}

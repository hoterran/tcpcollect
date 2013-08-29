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

#define DROP_SAMPLE_TABLE "DROP TABLE IF EXISTS test_table"
#define CREATE_SAMPLE_TABLE "CREATE TABLE test_table(col1 INT, col2 varchar(40))"
#define INSERT_SAMPLE "INSERT INTO test_table(col1, col2) VALUES(?,?)"

int main (int argc, char *argv[]) {

    MYSQL *mysql;
    MYSQL_RES *result;
    MYSQL_ROW row;
    my_bool reconnect = 0;
    mysql = mysql_init(NULL);
    mysql_options(mysql, MYSQL_OPT_RECONNECT, &reconnect);

    CONN(0);

    my_ulonglong  affected_rows;
    int           param_count;
    short         small_data;
    int           int_data;
    char          str_data[STRING_SIZE];
    unsigned long str_length;
    my_bool       is_null;

    if (mysql_query(mysql, DROP_SAMPLE_TABLE))
    {
      fprintf(stderr, " DROP TABLE failed\n");
      fprintf(stderr, " %s\n", mysql_error(mysql));
      exit(0);
    }

    if (mysql_query(mysql, CREATE_SAMPLE_TABLE))
    {
      fprintf(stderr, " CREATE TABLE failed\n");
      fprintf(stderr, " %s\n", mysql_error(mysql));
      exit(0);
    }

    //1---
    MYSQL_STMT    *stmt;
    MYSQL_BIND    bind[2];

    stmt = mysql_stmt_init(mysql);
    mysql_stmt_prepare(stmt, INSERT_SAMPLE, strlen(INSERT_SAMPLE));

    memset(bind, 0, sizeof(bind));
    bind[0].buffer_type= MYSQL_TYPE_LONGLONG;
    bind[0].buffer= (char *)&int_data;
    bind[0].is_null= 0;
    bind[1].buffer_type= MYSQL_TYPE_STRING;
    bind[1].buffer= (char *)str_data;
    bind[1].is_null= 0;
    bind[1].length= &str_length;        //实际大小, bind_
    mysql_stmt_bind_param(stmt, bind);

    int_data= 10;             /* integer */
    strncpy(str_data, "MySQL", STRING_SIZE); /* string  */
    str_length= strlen(str_data);
    mysql_stmt_execute(stmt); //success
    mysql_stmt_execute(stmt); //success
    mysql_stmt_execute(stmt); //success
    mysql_stmt_execute(stmt); //success
    mysql_stmt_execute(stmt); //success
    mysql_stmt_execute(stmt); //success

    mysql_stmt_close(stmt);

    // no cursor
    stmt = mysql_stmt_init(mysql);
    char *sql = "select 1 from test_table";
    unsigned long type = (unsigned long) CURSOR_TYPE_NO_CURSOR;
    mysql_stmt_attr_set(stmt, STMT_ATTR_CURSOR_TYPE, (void*) &type);
    mysql_stmt_prepare(stmt, sql, strlen(sql));
    mysql_stmt_execute(stmt); //success
    mysql_stmt_close(stmt);

    // cursor read only
    stmt = mysql_stmt_init(mysql);
    sql = "select * from test_table";
    type = (unsigned long) CURSOR_TYPE_READ_ONLY;
    mysql_stmt_attr_set(stmt, STMT_ATTR_CURSOR_TYPE, (void*) &type);
    mysql_stmt_prepare(stmt, sql, strlen(sql));
    mysql_stmt_execute(stmt); // not return resultset

    memset(bind, 0, sizeof(bind));

    bind[0].buffer_type= MYSQL_TYPE_LONG;
    bind[0].buffer= (char *)&int_data;

    bind[1].buffer_type= MYSQL_TYPE_STRING;
    bind[1].buffer= (char *)str_data;
    bind[1].buffer_length= STRING_SIZE;
    mysql_stmt_bind_result(stmt, bind);
    mysql_stmt_store_result(stmt);

    int row_count = 0;
    while(!mysql_stmt_fetch(stmt)) { // here return resultset
        printf("%d - %s\n", int_data, str_data); 
    }

    mysql_stmt_close(stmt);

    // set num 
    stmt = mysql_stmt_init(mysql);
    sql = "select a.* from test_table a";
    type = (unsigned long) CURSOR_TYPE_READ_ONLY;
    unsigned long prefetch_rows = 2;
    mysql_stmt_attr_set(stmt, STMT_ATTR_CURSOR_TYPE, (void*) &type);
    mysql_stmt_attr_set(stmt, STMT_ATTR_PREFETCH_ROWS, (void*) &prefetch_rows);

    mysql_stmt_prepare(stmt, sql, strlen(sql));
    mysql_stmt_execute(stmt); // not return resultset

    memset(bind, 0, sizeof(bind));

    bind[0].buffer_type= MYSQL_TYPE_LONG;
    bind[0].buffer= (char *)&int_data;

    bind[1].buffer_type= MYSQL_TYPE_STRING;
    bind[1].buffer= (char *)str_data;
    bind[1].buffer_length= STRING_SIZE;
    mysql_stmt_bind_result(stmt, bind);
    mysql_stmt_store_result(stmt);

    row_count = 0;
    while(!mysql_stmt_fetch(stmt)) { // here return resultset
        printf("#####%d - %s\n", int_data, str_data); 
    }

    mysql_stmt_close(stmt);
}

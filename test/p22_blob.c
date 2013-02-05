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
    if (!(sock = CONN(CLIENT_MULTI_STATEMENTS))) {
        fprintf(stderr, "Couldn't connect to engine!\n%s\n\n", mysql_error(mysql));
        perror("");
        exit(1);
    }

    // simple 
    char sql[100] = {};

    sprintf(sql, "INSERT INTO blob_test(a, b) VALUE (1, 2)");

    mysql_query(sock, sql);

    mysql_query(sock, "select * from blob_test");
    
    result = mysql_store_result(mysql);
    mysql_free_result(result);

    //prepare

    MYSQL_STMT    *stmt;
    MYSQL_BIND    bind[2];
    my_ulonglong  affected_rows;
    int           param_count;
    short         small_data;
    int           int_data;
    char          str_data[1000];
    unsigned long str_length;
    my_bool       is_null;

    stmt = mysql_stmt_init(mysql);

    sprintf(sql, "INSERT INTO blob_test(a, b) VALUE (?, ?)");
    mysql_stmt_prepare(stmt, sql, strlen(sql));

    memset(bind, 0, sizeof(bind));

    /* INTEGER PARAM */
    /* This is a number type, so there is no need to specify buffer_length */
    bind[0].buffer_type= MYSQL_TYPE_LONG;
    bind[0].buffer= (char *)&int_data;
    bind[0].is_null= 0;

    /* STRING PARAM */
    my_bool a = 1;
    bind[1].buffer_type= MYSQL_TYPE_BLOB;
    bind[1].buffer= (char *)str_data;
    bind[1].is_null= &a;
    bind[1].length= &str_length;        //实际大小, bind_

    mysql_stmt_bind_param(stmt, bind);

    /* Specify the data values for the first row -------------------------------------------------- */
    int_data= 10;             /* integer */
    strncpy(str_data, "MySQL", 1000); /* string  */
    str_length= strlen(str_data);

    mysql_stmt_execute(stmt);

    mysql_stmt_close(stmt);

    return 0;
}


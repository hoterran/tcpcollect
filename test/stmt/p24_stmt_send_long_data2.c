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

    // simple 
    char sql[100] = {};

    sprintf(sql, "INSERT INTO blob_test(a, b) VALUE (1, 2)");

    mysql_query(sock, sql);

    mysql_query(sock, "select * from blob_test");
    
    result = mysql_store_result(mysql);
    mysql_free_result(result);

    #define INSERT_QUERY "INSERT INTO blob_test(a, b) VALUES(?,?)"

    MYSQL_STMT    *stmt;
    MYSQL_BIND bind[2];
    long       length;
    int         int_data = 10;
    char        str[100];
    int         ret;

    stmt = mysql_stmt_init(mysql);

    mysql_stmt_prepare(stmt, INSERT_QUERY, strlen(INSERT_QUERY));

    memset(bind, 0, sizeof(bind));
    bind[0].buffer_type= MYSQL_TYPE_LONG;
    bind[0].buffer= (char *)&int_data;
    bind[0].is_null= 0;
    bind[1].buffer_type= MYSQL_TYPE_BLOB;
    bind[1].buffer = (char*)&str;
    bind[1].is_null= 0;
    mysql_stmt_bind_param(stmt, bind);

    ret = mysql_stmt_send_long_data(stmt,1,"fails",5);

    ret = mysql_stmt_send_long_data(stmt,1," - The most popular Open Source database",40);

    mysql_stmt_execute(stmt);

    mysql_stmt_close(stmt);

    stmt = mysql_stmt_init(mysql);

    mysql_stmt_prepare(stmt, INSERT_QUERY, strlen(INSERT_QUERY));

    size_t s = sizeof(str);

    memset(bind, 0, sizeof(bind));
    bind[0].buffer_type= MYSQL_TYPE_LONG;
    bind[0].buffer= (char *)&int_data;
    bind[0].is_null= 0;
    bind[1].buffer_type= MYSQL_TYPE_BLOB;
    bind[1].buffer = (char*)&str;
    bind[1].is_null= 0;
    bind[1].length= (char*)&s;
    mysql_stmt_bind_param(stmt, bind);

    snprintf(str, sizeof(str), "%s", "this success");

    mysql_stmt_execute(stmt);

    mysql_stmt_close(stmt);

    return 0;
}


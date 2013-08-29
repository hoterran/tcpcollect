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
    CONN(0);

    // simple 
    #define QUERY "select longcol, bytecol from test1 where bytecol = ? and stringcol = ?"

    MYSQL_STMT    *stmt;
    MYSQL_BIND bind[2];
    long       length;
    char        tiny_data ;
    long long   long_data;
    char        str[100];
    int         ret;

    stmt = mysql_stmt_init(mysql);

    mysql_stmt_prepare(stmt, QUERY, strlen(QUERY));

    memset(bind, 0, sizeof(bind)); 
    bind[0].buffer_type= MYSQL_TYPE_TINY;
    bind[0].buffer= (char *)&tiny_data;
    bind[0].is_null= 0;

    bind[1].buffer_type= MYSQL_TYPE_STRING;
    bind[1].buffer= (char *)&str;
    bind[1].is_null= 0;
    bind[1].length = &length;
    mysql_stmt_bind_param(stmt, bind);

    ret = mysql_stmt_send_long_data(stmt,1,"888888'888888888",strlen("88888'8888888888"));

    //ret = mysql_stmt_send_long_data(stmt,1," - The most popular Open Source database",40);

    MYSQL_BIND    bResult[2];
    memset(bResult, 0, sizeof(bResult)); 
    bResult[0].buffer_type= MYSQL_TYPE_LONGLONG;
    bResult[0].buffer= (char *)&long_data;

    bResult[1].buffer_type= MYSQL_TYPE_TINY;
    bResult[1].buffer= (char *)&tiny_data;

    mysql_stmt_bind_result(stmt, bResult);

    tiny_data = 1;
    mysql_stmt_execute(stmt);

    mysql_stmt_store_result(stmt); 

    int ii = 0;
    while(!mysql_stmt_fetch(stmt)) {
        printf("1- %d[%lld, %d]\n",  ii++,
            long_data, tiny_data); 
    }

    tiny_data = 5;
    snprintf(str, sizeof(str), "%s", "99\"9'9");
    length = strlen(str);

    mysql_stmt_execute(stmt);

    mysql_stmt_store_result(stmt); 

    while(!mysql_stmt_fetch(stmt)) {
        printf("2- %d[%lld, %d\n",  ii++,
            long_data, tiny_data); 
    }

    // two section
    ret = mysql_stmt_send_long_data(stmt,1,"8888888888888",strlen("8888888888888"));
    ret = mysql_stmt_send_long_data(stmt,1,"88",strlen("88"));

    tiny_data = 1;
    mysql_stmt_execute(stmt);

    mysql_stmt_store_result(stmt); 

    while(!mysql_stmt_fetch(stmt)) {
        printf("3- %d[%lld, %d]\n",  ii++,
            long_data, tiny_data); 
    }

    // test reset is ok TODO
    return 0;
}


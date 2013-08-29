#include <stdio.h>
#include <mysql.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "c.h"
#define STRING_SIZE 1024

int main (int argc, char *argv[]) {

    MYSQL *mysql;
    MYSQL_RES *result;
    MYSQL_ROW row;
    my_bool reconnect = 0;
    mysql = mysql_init(NULL);
    mysql_options(mysql, MYSQL_OPT_RECONNECT, &reconnect);

    CONN(0);

    MYSQL_STMT    *stmt, *stmt2;
    MYSQL_BIND    bind[1];
    MYSQL_BIND    bResult[1];
    MYSQL_BIND    bResult2[1];
    unsigned long length[1];
    my_ulonglong  affected_rows;
    short         small_data;
    long long   long_data;
    char       int_data;
    my_bool       is_null;

    stmt = mysql_stmt_init(mysql);
    stmt2 = mysql_stmt_init(mysql);

    char *normalSql = "select longcol from test1 where bytecol = 1";
    char *stmtSql = "select longcol from test1 where bytecol = ?";
    //1
    mysql_stmt_prepare(stmt, stmtSql, strlen(stmtSql));
    memset(bind, 0, sizeof(bind));
    bind[0].buffer_type= MYSQL_TYPE_TINY;
    bind[0].buffer= (char *)&int_data;
    bind[0].is_null= 0;
    mysql_stmt_bind_param(stmt, bind);
    //2
    mysql_stmt_prepare(stmt2, normalSql, strlen(normalSql));
    //3
    mysql_query(mysql, normalSql);
    result = mysql_store_result(mysql);
    while(mysql_fetch_row(result));
    mysql_free_result(result);

    //2
    memset(bResult2, 0, sizeof(bResult2));
    bResult2[0].buffer_type= MYSQL_TYPE_LONGLONG;
    bResult2[0].buffer= (char *)&long_data;
    bResult2[0].is_null= &is_null;
    bResult2[0].length= &length[0];
    mysql_stmt_bind_result(stmt2, bResult2);

    //1
    memset(bResult, 0, sizeof(bResult));
    bResult[0].buffer_type= MYSQL_TYPE_LONGLONG;
    bResult[0].buffer= (char *)&long_data;
    bResult[0].is_null= &is_null;
    bResult[0].length= &length[0];
    mysql_stmt_bind_result(stmt, bResult);

    int_data= 1;
    mysql_stmt_execute(stmt2);
    mysql_stmt_store_result(stmt2); 

    while(!mysql_stmt_fetch(stmt2)) {
        printf("2[%lld]\n", long_data); 
    }
    //must execute -> store->fetch over,then mysql is ready status
    // other execute 
    mysql_stmt_execute(stmt);
    mysql_stmt_store_result(stmt); 

    while(!mysql_stmt_fetch(stmt)) {
        printf("1[%lld]\n", long_data); 
    }

    mysql_query(mysql, normalSql);

    result = mysql_store_result(mysql);

    while(mysql_fetch_row(result));

    mysql_free_result(result);

    int_data= 1;
    mysql_stmt_execute(stmt);
    mysql_stmt_store_result(stmt); 
    while(!mysql_stmt_fetch(stmt)) {
        printf("3[%lld]\n", long_data); 
    }

    mysql_stmt_execute(stmt2);

    mysql_stmt_store_result(stmt2); 

    while(!mysql_stmt_fetch(stmt2)) {
        printf("4[%lld]\n", long_data); 
    }

    mysql_stmt_reset(stmt);
    mysql_stmt_close(stmt);
}

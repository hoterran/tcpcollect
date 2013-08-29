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

    MYSQL_STMT    *stmt;
    MYSQL_BIND    bind[1];
    MYSQL_BIND    bResult[1];
    unsigned long length[1];
    my_ulonglong  affected_rows;
    short         small_data;
    long long       int_data;
    char tiny_data;
    my_bool       is_null;

    stmt = mysql_stmt_init(mysql);
    
    // normal
    // field > 0 and param > 0 
    char *stmtSql = "select longcol from test1 where longcol > ?";

    mysql_stmt_prepare(stmt, stmtSql, strlen(stmtSql));

    memset(bind, 0, sizeof(bind));
    bind[0].buffer_type= MYSQL_TYPE_LONGLONG;
    bind[0].buffer= (char *)&int_data;
    bind[0].is_null= 0;
    mysql_stmt_bind_param(stmt, bind);

    memset(bResult, 0, sizeof(bResult));
    bResult[0].buffer_type= MYSQL_TYPE_LONGLONG;
    bResult[0].buffer= (char *)&int_data;
    bResult[0].is_null= &is_null;
    bResult[0].length= &length[0];
    mysql_stmt_bind_result(stmt, bResult);

    int_data= 1;
    mysql_stmt_execute(stmt);
    mysql_stmt_store_result(stmt); 

    while(!mysql_stmt_fetch(stmt)) {
        printf("1[%lld]\n", int_data); 
    }

    int_data= 100;
    mysql_stmt_execute(stmt);
    mysql_stmt_store_result(stmt); 

    while(!mysql_stmt_fetch(stmt)) {
        printf("2[%lld]\n", int_data); 
    }

    int_data= 300;
    mysql_stmt_execute(stmt);
    mysql_stmt_store_result(stmt); 

    while(!mysql_stmt_fetch(stmt)) {
        printf("3[%lld]\n", int_data); 
    }
    
    // param  = 0 and field > 0
    char *stmtSql2 = "select longcol from test1 where longcol > 1 limit 15";

    mysql_stmt_prepare(stmt, stmtSql2, strlen(stmtSql2));

    memset(bResult, 0, sizeof(bResult));
    bResult[0].buffer_type= MYSQL_TYPE_LONGLONG;
    bResult[0].buffer= (char *)&int_data;
    bResult[0].is_null= &is_null;
    bResult[0].length= &length[0];
    mysql_stmt_bind_result(stmt, bResult);

    mysql_stmt_execute(stmt);
    mysql_stmt_store_result(stmt); 

    while(!mysql_stmt_fetch(stmt)) {
        printf("3[%lld]\n", int_data); 
    }

    // field = 0 and param > 0

    char *stmtSql3 = "insert into test1(bytecol) values (?)";

    mysql_stmt_prepare(stmt, stmtSql3, strlen(stmtSql3));

    memset(bind, 0, sizeof(bind));
    bind[0].buffer_type= MYSQL_TYPE_TINY;
    bind[0].buffer= (char *)&tiny_data;
    bind[0].is_null= 0;
    mysql_stmt_bind_param(stmt, bind);

    tiny_data = 1;
    mysql_stmt_execute(stmt);

    // param = 0 and field = 0
    char *stmtSql4 = "insert into test1(bytecol) values (10)";

    mysql_stmt_prepare(stmt, stmtSql4, strlen(stmtSql4));
    mysql_stmt_execute(stmt);
    
    mysql_stmt_reset(stmt);
    mysql_stmt_close(stmt);
}

#include <stdio.h>
#include <mysql.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "c.h"

int main (int argc, char *argv[]) {

    MYSQL *mysql;
    MYSQL_RES *result;
    MYSQL_ROW row;
    my_bool reconnect = 0;
    MYSQL_STMT    *stmt;
    MYSQL_BIND    bind[1];
    MYSQL_BIND    bResult[1];
    unsigned long length[1];
    int        int_data;

    mysql = mysql_init(NULL);
    mysql_options(mysql, MYSQL_OPT_RECONNECT, &reconnect);
    CONN(0);

    char *normalSql = "select intcol from test1 where intcol > 1";
    // 1. normal buffer
    mysql_query(mysql, normalSql);
    result = mysql_store_result(mysql);
    while(row = mysql_fetch_row(result)) {
        printf("1 - %d\n", atoi(row[0]));
    }
    mysql_free_result(result);

    // 2. normal unbuffer
    mysql_query(mysql, normalSql);
    result = mysql_use_result(mysql);
    while(row = mysql_fetch_row(result)) {
        printf("2 - %d\n", atoi(row[0]));
    }
    mysql_free_result(result);

    char *stmtSql = "select intcol from test1 where intcol > ?";

    //3. stmt buffer
    stmt = mysql_stmt_init(mysql);

    mysql_stmt_prepare(stmt, stmtSql, strlen(stmtSql));

    memset(bind, 0, sizeof(bind));
    bind[0].buffer_type= MYSQL_TYPE_LONG;
    bind[0].buffer= (char *)&int_data;
    mysql_stmt_bind_param(stmt, bind);

    memset(bResult, 0, sizeof(bResult));
    bResult[0].buffer_type= MYSQL_TYPE_LONG;
    bResult[0].buffer= (char *)&int_data;
    mysql_stmt_bind_result(stmt, bResult);

    int_data= 1;
    mysql_stmt_execute(stmt);
    mysql_stmt_store_result(stmt); 

    while(!mysql_stmt_fetch(stmt)) {
        printf("3 - %d \n", int_data); 
    }

    mysql_stmt_close(stmt);

    // 4. stmt unbuffer
    stmt = mysql_stmt_init(mysql);

    mysql_stmt_prepare(stmt, stmtSql, strlen(stmtSql));

    memset(bind, 0, sizeof(bind));
    bind[0].buffer_type= MYSQL_TYPE_LONG;
    bind[0].buffer= (char *)&int_data;
    mysql_stmt_bind_param(stmt, bind);

    memset(bResult, 0, sizeof(bResult));
    bResult[0].buffer_type= MYSQL_TYPE_LONG;
    bResult[0].buffer= (char *)&int_data;
    mysql_stmt_bind_result(stmt, bResult);

    int_data= 1;
    mysql_stmt_execute(stmt);

    while(!mysql_stmt_fetch(stmt)) {
        printf("4 - %d \n", int_data); 
    }
    
    mysql_stmt_close(stmt);

    // 5. stmt server cursor default
    stmt = mysql_stmt_init(mysql);

    mysql_stmt_prepare(stmt, stmtSql, strlen(stmtSql));

    unsigned long type = (unsigned long) CURSOR_TYPE_READ_ONLY;
    mysql_stmt_attr_set(stmt, STMT_ATTR_CURSOR_TYPE, (void*) &type);

    memset(bind, 0, sizeof(bind));
    bind[0].buffer_type= MYSQL_TYPE_LONG;
    bind[0].buffer= (char *)&int_data;
    mysql_stmt_bind_param(stmt, bind);

    memset(bResult, 0, sizeof(bResult));
    bResult[0].buffer_type= MYSQL_TYPE_LONG;
    bResult[0].buffer= (char *)&int_data;
    mysql_stmt_bind_result(stmt, bResult);

    int_data= 1;
    mysql_stmt_execute(stmt);

    while(!mysql_stmt_fetch(stmt)) {
        printf("5 - %d \n", int_data); 
    }
    
    mysql_stmt_close(stmt);


    // 6. stmt server cursor setting
    stmt = mysql_stmt_init(mysql);

    mysql_stmt_prepare(stmt, stmtSql, strlen(stmtSql));

    type = (unsigned long) CURSOR_TYPE_READ_ONLY;
    mysql_stmt_attr_set(stmt, STMT_ATTR_CURSOR_TYPE, (void*) &type);

    unsigned long prefetch_rows = 2;
    mysql_stmt_attr_set(stmt, STMT_ATTR_PREFETCH_ROWS, (void*) &prefetch_rows);

    memset(bind, 0, sizeof(bind));
    bind[0].buffer_type= MYSQL_TYPE_LONG;
    bind[0].buffer= (char *)&int_data;
    mysql_stmt_bind_param(stmt, bind);

    memset(bResult, 0, sizeof(bResult));
    bResult[0].buffer_type= MYSQL_TYPE_LONG;
    bResult[0].buffer= (char *)&int_data;
    mysql_stmt_bind_result(stmt, bResult);

    int_data= 1;
    mysql_stmt_execute(stmt);

    while(!mysql_stmt_fetch(stmt)) {
        printf("6 - %d \n", int_data); 
    }
    
    mysql_stmt_close(stmt);

    mysql_close(mysql);
}

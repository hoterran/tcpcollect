#include <stdio.h>
#include <mysql.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "c.h"
#define STRING_SIZE 1024

#define SELECT_SAMPLE "SELECT c1 from a1"

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
    MYSQL_RES     *prepare_meta_result;
    MYSQL_TIME    ts;
    unsigned long length[1];
    int           param_count, column_count, row_count;
    short         small_data;
    int           int_data;
    char          str_data[STRING_SIZE];
    my_bool       is_null[1];

    // 1. no cursor
    stmt = mysql_stmt_init(mysql);
    mysql_stmt_prepare(stmt, SELECT_SAMPLE, strlen(SELECT_SAMPLE));
    param_count= mysql_stmt_param_count(stmt);
    //prepare_meta_result = mysql_stmt_result_metadata(stmt);
    mysql_stmt_execute(stmt);

    memset(bind, 0, sizeof(bind));

    bind[0].buffer_type= MYSQL_TYPE_LONG;
    bind[0].buffer= (char *)&int_data;
    bind[0].is_null= &is_null[0];
    bind[0].length= &length[0];

    mysql_stmt_bind_result(stmt, bind);
    //mysql_stmt_store_result(stmt);

    while (!mysql_stmt_fetch(stmt)) {
        printf("1 - %d \n", int_data); 
    }

    mysql_stmt_close(stmt);


    // 2. cursor read only
    stmt = mysql_stmt_init(mysql);

    unsigned long type = (unsigned long) CURSOR_TYPE_READ_ONLY;
    mysql_stmt_attr_set(stmt, STMT_ATTR_CURSOR_TYPE, (void*) &type);

    mysql_stmt_prepare(stmt, SELECT_SAMPLE, strlen(SELECT_SAMPLE));
    param_count= mysql_stmt_param_count(stmt);
    //prepare_meta_result = mysql_stmt_result_metadata(stmt);
    mysql_stmt_execute(stmt);

    memset(bind, 0, sizeof(bind));

    bind[0].buffer_type= MYSQL_TYPE_LONG;
    bind[0].buffer= (char *)&int_data;
    bind[0].is_null= &is_null[0];
    bind[0].length= &length[0];

    mysql_stmt_bind_result(stmt, bind);
    //mysql_stmt_store_result(stmt); // default 1

    while (!mysql_stmt_fetch(stmt)) {
        printf("1 - %d \n", int_data); 
    }

    mysql_stmt_close(stmt);

    // 3. set num 
    stmt = mysql_stmt_init(mysql);

    type = (unsigned long) CURSOR_TYPE_READ_ONLY;
    unsigned long prefetch_rows = 2;
    mysql_stmt_attr_set(stmt, STMT_ATTR_CURSOR_TYPE, (void*) &type);
    mysql_stmt_attr_set(stmt, STMT_ATTR_PREFETCH_ROWS, (void*) &prefetch_rows);

    mysql_stmt_prepare(stmt, SELECT_SAMPLE, strlen(SELECT_SAMPLE));
    param_count= mysql_stmt_param_count(stmt);
    //prepare_meta_result = mysql_stmt_result_metadata(stmt);
    mysql_stmt_execute(stmt);

    memset(bind, 0, sizeof(bind));

    bind[0].buffer_type= MYSQL_TYPE_LONG;
    bind[0].buffer= (char *)&int_data;
    bind[0].is_null= &is_null[0];
    bind[0].length= &length[0];

    mysql_stmt_bind_result(stmt, bind);
    //mysql_stmt_store_result(stmt);

    while (!mysql_stmt_fetch(stmt)) {
        printf("1 - %d \n", int_data); 
    }

    mysql_stmt_close(stmt);
}

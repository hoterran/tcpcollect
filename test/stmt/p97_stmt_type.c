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
    MYSQL_BIND    bResult[13];
    unsigned long length[3];

    long long       long_data;
    char        tiny_data;
    char        blob[1000];
    MYSQL_TIME   date;
    char        decimal[1000];
    double      d;
    float       f;
    int         i;
    short       s;
    int         m;
    char        str[1000];
    MYSQL_TIME  time;
    MYSQL_TIME  timestamp;
    // TODO datetime
    // year type 
    
    length[0] = sizeof(str);
    length[1] = sizeof(str);
    length[2] = sizeof(str);

    stmt = mysql_stmt_init(mysql);

    char *normalSql = "select * from test1";
    char *stmtSql = "select longcol, bytecol, blobcol, datecol, decimalcol, doublecol, floatcol, intcol, nullcol, shortcol, medcol, stringcol, timecol, timestampcol from test1 where bytecol = ?";

    mysql_stmt_prepare(stmt, stmtSql, strlen(stmtSql));

    /* Bind the data for all 3 parameters */

    memset(bind, 0, sizeof(bind));

    bind[0].buffer_type= MYSQL_TYPE_TINY;
    bind[0].buffer= (char *)&tiny_data;
    bind[0].is_null= 0;

    mysql_stmt_bind_param(stmt, bind);

    mysql_query(mysql, normalSql);

    result = mysql_store_result(mysql);

    while(mysql_fetch_row(result));

    mysql_free_result(result);

    /* --- */
    memset(bResult, 0, sizeof(bResult));

    bResult[0].buffer_type= MYSQL_TYPE_LONGLONG;
    bResult[0].buffer= (char *)&long_data;

    bResult[1].buffer_type= MYSQL_TYPE_TINY;
    bResult[1].buffer= (char *)&tiny_data;

    bResult[2].buffer_type= MYSQL_TYPE_BLOB;
    bResult[2].buffer= (char *)&blob;
    bResult[2].buffer_length = length[0];

    bResult[3].buffer_type= MYSQL_TYPE_DATE;
    bResult[3].buffer= (char *)&date;

    bResult[4].buffer_type= MYSQL_TYPE_DECIMAL;
    bResult[4].buffer= (char *)&decimal;
    bResult[4].buffer_length= length[1];

    bResult[5].buffer_type= MYSQL_TYPE_DOUBLE;
    bResult[5].buffer= (char *)&d;

    bResult[6].buffer_type= MYSQL_TYPE_FLOAT;
    bResult[6].buffer= (char *)&f;

    bResult[7].buffer_type= MYSQL_TYPE_LONG;
    bResult[7].buffer= (char *)&i;

    bResult[8].buffer_type= MYSQL_TYPE_NULL;

    bResult[9].buffer_type= MYSQL_TYPE_SHORT;
    bResult[9].buffer= (char *)&s;

    bResult[10].buffer_type= MYSQL_TYPE_INT24;
    bResult[10].buffer= (char *)&m;

    bResult[11].buffer_type= MYSQL_TYPE_STRING;
    bResult[11].buffer= (char *)&str;
    bResult[11].buffer_length = length[2];

    bResult[12].buffer_type= MYSQL_TYPE_TIME;
    bResult[12].buffer= (char *)&time;

    bResult[13].buffer_type= MYSQL_TYPE_TIMESTAMP;
    bResult[13].buffer= (char *)&timestamp;

    mysql_stmt_bind_result(stmt, bResult);

    //singnode
    tiny_data = 1;
    mysql_stmt_execute(stmt);

    mysql_stmt_store_result(stmt); 

    int ii = 0;
    while(!mysql_stmt_fetch(stmt)) {
        printf("%d[%lld, %d, %s, %lf, %f, %d, %hd, %d, %s]\n",  ii++,
            long_data, tiny_data, decimal, d, f, i, s, m, str); 
    }

    mysql_query(mysql, normalSql);

    result = mysql_store_result(mysql);

    while(mysql_fetch_row(result));

    mysql_free_result(result);

    //singnode;
    tiny_data = 2;

    mysql_stmt_execute(stmt);

    mysql_stmt_store_result(stmt); 

    while(!mysql_stmt_fetch(stmt)) {
        printf("%d[%lld, %d, %s, %lf, %f, %d, %hd, %d, %s, %u, %u, %u, %u,%u,%u, %u, %u, %u, %u, %u, %u ]\n", ii++,
            long_data, tiny_data, decimal, d, f, i, s, m, str, 
            date.year, date.month, date.day, time.hour, time.minute, time.second, 
            timestamp.year, timestamp.month, timestamp.day, timestamp.hour, timestamp.minute, timestamp.second); 
    }

    mysql_stmt_reset(stmt);
    mysql_stmt_close(stmt);
}

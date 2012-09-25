#include <stdio.h>
#include <mysql.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#define STRING_SIZE 1024

/*

MYSQL_TYPE_TIMESTAMP    TIMESTAMP field
MYSQL_TYPE_DATE         DATE field
MYSQL_TYPE_TIME         TIME field
MYSQL_TYPE_DATETIME     DATETIME field

*/

#define DROP_SAMPLE_TABLE "DROP TABLE IF EXISTS test_table"
#define CREATE_SAMPLE_TABLE "CREATE TABLE test_table(col1 INT, col2 VARCHAR(40), col3 SMALLINT, col4 TIMESTAMP, col5 datetime, col6 date, col7 time)"
#define INSERT_SAMPLE "INSERT INTO test_table(col1,col2,col3, col4, col5, col6, col7) VALUES(?,?,?,?,?,?,?)"
int main (int argc, char *argv[]) {

    MYSQL *mysql;
    MYSQL_RES *result;
    MYSQL_ROW row;
    my_bool reconnect = 0;
    mysql = mysql_init(NULL);
    mysql_options(mysql, MYSQL_OPT_RECONNECT, &reconnect);
 
    mysql_real_connect(mysql, "127.0.0.1", "root", "root", "test", 3306, NULL, 0);

    MYSQL_STMT    *stmt;
    MYSQL_BIND    bind[7];
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

    /* Prepare an INSERT query with 3 parameters */
    /* (the TIMESTAMP column is not named; the server */
    /*  sets it to the current date and time) */
    stmt = mysql_stmt_init(mysql);
    if (!stmt)
    {
      fprintf(stderr, " mysql_stmt_init(), out of memory\n");
      exit(0);
    }
    if (mysql_stmt_prepare(stmt, INSERT_SAMPLE, strlen(INSERT_SAMPLE)))
    {
      fprintf(stderr, " mysql_stmt_prepare(), INSERT failed\n");
      fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
      exit(0);
    }
    fprintf(stdout, " prepare, INSERT successful\n");

    /* Get the parameter count from the statement */
    param_count= mysql_stmt_param_count(stmt);
    fprintf(stdout, " total parameters in INSERT: %d\n", param_count);

    if (param_count != 7) /* validate parameter count */
    {
      fprintf(stderr, " invalid parameter count returned by MySQL\n");
      exit(0);
    }

    /* Bind the data for all 3 parameters */

    memset(bind, 0, sizeof(bind));

    /* INTEGER PARAM */
    /* This is a number type, so there is no need to specify buffer_length */
    bind[0].buffer_type= MYSQL_TYPE_LONG;
    bind[0].buffer= (char *)&int_data;
    bind[0].is_null= 0;

    /* STRING PARAM */
    bind[1].buffer_type= MYSQL_TYPE_STRING;
    bind[1].buffer= (char *)str_data;
    //bind[1].buffer_length= STRING_SIZE;  //最大长度, string not use this, 其它类型buffer_length 也没用
    bind[1].is_null= 0;
    bind[1].length= &str_length;        //实际大小, bind_

    /* SMALLINT PARAM */
    bind[2].buffer_type= MYSQL_TYPE_SHORT;
    bind[2].buffer= (char *)&small_data;
    bind[2].is_null= &is_null;

    /* timestamp */

    MYSQL_TIME t;
    bind[3].buffer_type= MYSQL_TYPE_TIMESTAMP;
    bind[3].buffer= (char*)&t;
    bind[3].is_null= 0;

    bind[4].buffer_type= MYSQL_TYPE_DATETIME;
    bind[4].buffer= (char*)&t;
    bind[4].is_null= 0;

    bind[5].buffer_type= MYSQL_TYPE_DATE;
    bind[5].buffer= (char*)&t;
    bind[5].is_null= 0;

    bind[6].buffer_type= MYSQL_TYPE_TIME;
    bind[6].buffer= (char*)&t;
    bind[6].is_null= 0;

    /* Bind the buffers */
    if (mysql_stmt_bind_param(stmt, bind))
    {
      fprintf(stderr, " mysql_stmt_bind_param() failed\n");
      fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
      exit(0);
    }

    /* Specify the data values for the first row -------------------------------------------------- */
    int_data= 10;             /* integer */
    strncpy(str_data, "MySQL", STRING_SIZE); /* string  */
    str_length= strlen(str_data);

    t.year= 2032;
    t.month= 02;
    t.day= 03;

    t.hour= 10;
    t.minute= 45;
    t.second= 20;

    /* INSERT SMALLINT data as NULL */
    is_null= 1;

    /* Execute the INSERT statement - 1*/
    if (mysql_stmt_execute(stmt))
    {
      fprintf(stderr, " mysql_stmt_execute(), 1 failed\n");
      fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
      exit(0);
    }

    /* Get the total number of affected rows */
    affected_rows= mysql_stmt_affected_rows(stmt);
    fprintf(stdout, " total affected rows(insert 1): %lu\n",
                    (unsigned long) affected_rows);

    if (affected_rows != 1) /* validate affected rows */
    {
      fprintf(stderr, " invalid affected rows by MySQL\n");
      exit(0);
    }

    /* Specify data values for second row, then re-execute the statement ----------------------------------------*/
    int_data= 1000;
    strncpy(str_data, "The most popular Open Source database", STRING_SIZE);
    str_length= strlen(str_data);
    small_data= 1000;         /* smallint */
    is_null= 0;               /* reset */

    /* Execute the INSERT statement - 2*/
    if (mysql_stmt_execute(stmt))
    {
      fprintf(stderr, " mysql_stmt_execute, 2 failed\n");
      fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
      exit(0);
    }

    /* Get the total rows affected */
    affected_rows= mysql_stmt_affected_rows(stmt);
    fprintf(stdout, " total affected rows(insert 2): %lu\n",
                    (unsigned long) affected_rows);

    if (affected_rows != 1) /* validate affected rows */
    {
      fprintf(stderr, " invalid affected rows by MySQL\n");
      exit(0);
    }

    /* Specify data values for third row, then re-execute the statement */
    int_data= 1000;
    strncpy(str_data, "The most popular Open Source database11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111", STRING_SIZE);
    str_length= strlen(str_data);
    small_data= 10000;         /* smallint */
    is_null= 0;               /* reset */

    /* Execute the INSERT statement - 2*/
    if (mysql_stmt_execute(stmt))
    {
      fprintf(stderr, " mysql_stmt_execute, 2 failed\n");
      fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
      exit(0);
    }

    /* Get the total rows affected */
    affected_rows= mysql_stmt_affected_rows(stmt);
    fprintf(stdout, " total affected rows(insert 2): %lu\n",
                    (unsigned long) affected_rows);

    if (affected_rows != 1) /* validate affected rows */
    {
      fprintf(stderr, " invalid affected rows by MySQL\n");
      exit(0);
    }
    /* Close the statement */
    if (mysql_stmt_close(stmt))
    {
      fprintf(stderr, " failed while closing the statement\n");
      fprintf(stderr, " %s\n", mysql_stmt_error(stmt));
      exit(0);
    }
}

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

    char *sql;

    int i;

    /*list dbs*/
    mysql_list_dbs(mysql, "");
    result = mysql_store_result(mysql);
    mysql_free_result(result);

    /* COM_FERESH */
    mysql_refresh(mysql, REFRESH_TABLES);

    /* COM_PROCESS_INFO */
    mysql_list_processes(mysql);
    result = mysql_store_result(mysql);
    mysql_free_result(result);

    /* create db */
    //mysql_create_db(mysql, "new_test");

    mysql_set_server_option(mysql, MYSQL_OPTION_MULTI_STATEMENTS_OFF);

    mysql_change_user(mysql, "kkk", "kkk", "test");

    sleep(3);
    mysql_close(mysql);

    return 0;
}

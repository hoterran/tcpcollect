#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "utils.h"
#include "log.h"
#include "adlist.h"

/* conclude user in list */
#define USERNAMEMAXLEN  32
#define TOKEN ','

int userMatch(void *ptr, void *key) {
    char *user = (char*)key;
    char *listValue = (char*)ptr;
    if (0 == strncmp(user, listValue, USERNAMEMAXLEN))
        return 1;
    else 
        return 0;
}

/* serperated by comma */
int initUserList(list *l, char *s) {
    ASSERT(l && s && (strlen(s) > 0));

    l->match = userMatch;
    char *p1 = NULL;
    char *head = s;
    int i = 0;

    while (NULL != (p1 = strchr(head, TOKEN))) {
        p1[0] = '\0'; 
        dump(L_DEBUG, "user:%s", head);
        listAddNodeHead(l, head);
        head = p1 + 1;
        i++;
    }

    dump(L_DEBUG, "user:%s", head);
    listAddNodeHead(l, head);
    i++;

    return i;
}

#ifdef _USER_TEST_

int main(int argc, char *argv[]) {

    list *l = listCreate();
    char u[] = "user1,user2,user3";
    ASSERT(3 == initUserList(l, u));

    ASSERT(listSearchKey(l, "user1"));
    ASSERT(listSearchKey(l, "user2"));
    ASSERT(listSearchKey(l, "user3"));
    ASSERT(NULL == listSearchKey(l, "user4"));

    /* wrong
        ASSERT(NULL == listSearchKey(l, "user1"));
    */

    return OK;
}

#endif 

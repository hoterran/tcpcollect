
#include <pcap.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "address.h"

struct address_list {
    struct in_addr in_addr;
    struct address_list *next;
};

AddressList*
get_addresses() {

    AddressList *al = malloc(sizeof(AddressList));
    AddressList *head = al;

    pcap_if_t *devlist, *curr;
    pcap_addr_t *addr;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&devlist, errbuf)) {
        fprintf(stderr, "pcap: %s\n", errbuf);
        return NULL;
    }
    
    for (curr = devlist; curr; curr = curr->next) {
//        if (curr->flags & PCAP_IF_LOOPBACK)
 //           continue;

        //printf("%s-%s-%p-%d\n", curr->name, curr->description, 
          //  curr->addresses, curr->flags);

        for (addr = curr->addresses; addr; addr = addr->next) {
            struct sockaddr *realaddr;

            //printf("\t %d %s \n", ((struct sockaddr_in *) addr->addr)->sin_addr.s_addr,
           //     inet_ntoa(((struct sockaddr_in *)addr->addr)->sin_addr));

            if (addr->addr)
                realaddr = addr->addr;
            else if (addr->dstaddr)
                realaddr = addr->dstaddr;
            else
                continue;
            
            if (realaddr->sa_family == AF_INET || 
                realaddr->sa_family == AF_INET6) {

                struct sockaddr_in *sin;
                
                sin = (struct sockaddr_in *) realaddr;
                
                al->next = malloc(sizeof(AddressList));
                if (!al->next)
                    abort();
                
                al->next->in_addr = sin->sin_addr;
                al->next->next = NULL;
                al= al->next;
            }
        }
    }
    
    pcap_freealldevs(devlist);
    
    return head;
}

/* address[] = "1.1.1.1, 2.2.2.2, 3.3.3.3*/
AddressList *
parse_addresses(char addresses[]) {

    AddressList *al = malloc(sizeof(AddressList));
    AddressList *head = al;

    char *next, *comma;
    next = addresses;
    
    while ((comma = strchr(next, ','))) {
        char *current;
        
        current = malloc((comma - next) + 1);
        if (!current)
            abort();
        
        strncpy(current, next, (comma - next));
        current[comma - next] = '\0';

        al->next = malloc(sizeof(AddressList));
        if (!al->next)
            abort();
        
        al->next->next = NULL;
        
        if (!inet_aton(current, &al->next->in_addr)) {
            free(current);
            //TODO
            return NULL;
            
        }
        
        al = al->next;
            
        free(current);

        next = comma + 1;
        
    }
    
    al->next = malloc(sizeof(AddressList));
    if (!al->next)
        abort();
    
    al->next->next = NULL;
    
    if (!inet_aton(next, &al->next->in_addr))
        return NULL;
    
    al = al->next;
            
    return head;
}

int
free_addresses(AddressList *al) {
    struct address_list *next;
    
    while (al->next) {
        next = al->next->next;
        free(al->next);
        al->next = next;
    }
    
    return 0;
    
}

int
is_local_address(AddressList *al, struct in_addr addr) {
    struct address_list *curr;
    
    for (curr = al->next; curr; curr = curr->next)
        if (curr->in_addr.s_addr == addr.s_addr)
            return 1;
        
    return 0;
}

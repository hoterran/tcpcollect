#ifndef LOCAL_ADDRESSES_H
#define LOCAL_ADDRESSES_H

#include <netinet/in.h>

struct address_list;
typedef struct address_list AddressList;

AddressList* get_addresses();
AddressList* parse_addresses(char []);

int free_addresses(AddressList *al);

int is_local_address(AddressList*, struct in_addr);

#endif

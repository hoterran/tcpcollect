
typedef unsigned short uint16;
typedef unsigned int uint;
typedef unsigned int uint32;
typedef unsigned char uchar;
typedef unsigned long ulong;

int is_sql (char *payload, int payload_len, char **user);

int parse_sql(char *payload, char** sql, int payload_len);

ulong parse_result(char* payload, int payload_len);

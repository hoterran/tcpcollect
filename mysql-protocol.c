#include <stdio.h>

typedef unsigned int uint;
typedef unsigned int uint32;
typedef unsigned char uchar;
typedef unsigned long ulong;

#define uint3korr(A)    (uint32) (((uint32) ((uchar) (A)[0])) +\
  (((uint32) ((uchar) (A)[1])) << 8) +\
  (((uint32) ((uchar) (A)[2])) << 16))

int error_packet(char *payload, int payload_len);
int ok_packet(char *payload, int payload_len);
int resultset_packet(char *payload, int payload_len, int num);
int eof_packet(char* payload, int payload_len);
int field_packet(char* payload, int payload_len, int field_number);
int parse_result(char* payload, int payload_len);

int parse_sql(char* payload, char** sql, int payload_len) {

    /*3 1 1 sql */
    int packet_length = uint3korr(payload);
    
    if (payload_len >= packet_length + 4) {
        //mysql packet is complete
        payload[4 + packet_length] = '\0';
        *sql = &payload[5];
        return payload[4]; // cmd
    }
    return -1;
}
/*
 *  ok
 *  error
 *  resultset
 *  if a complete resultset size larger than tcp packet will failure
 */
int parse_result(char* payload, int payload_len) {

    /*header*/
    if (payload_len > 4) {
        int header_packet_length = uint3korr(payload);
       
       if (header_packet_length + 4 <= payload_len) {
            uchar c = payload[4];
            if (c == 0) {
                return ok_packet(payload, payload_len);
            } else if (c == 0xff) {
                return error_packet(payload, payload_len); 
            } else {
                /* resultset */
                /* #TODO lcb */
                int field_number = c;
                return field_packet(payload + 4 + 1, payload_len - 4 - 1, field_number);
            }
       }
    } 
    return -1;
}

int field_packet(char* payload, int payload_len, int field_number) {

    if (field_number == 0)
        return eof_packet(payload, payload_len);
    else {
        if (payload_len > 4) {
            int field_packet_length = uint3korr(payload);
            /* dont care content, so skip it */
            if (field_packet_length + 4 < payload_len) {
                return field_packet(payload + 4 + field_packet_length, 
                    payload_len - 4 - field_packet_length, field_number - 1);
            }
        }
    }
    return -1;
}

int eof_packet(char* payload, int payload_len) {

    if (payload_len > 4) {
        uchar c = payload[4]; 
        if (c == 0xfe) {
            return resultset_packet(payload + 4 + 5, payload_len - 4 - 5, 0); 
        }
    }
    return -1;
}

int resultset_packet(char *payload, int payload_len, int num) {

    if (payload_len > 4) {
        int resultset_packet_length = uint3korr(payload);
        if (resultset_packet_length + 4 <= payload_len) {
            uchar c = payload[4];
            if (c == 0xfe) {
                return num; 
            } else {
                /* resultset */
                return resultset_packet(payload + 4 + resultset_packet_length,
                    payload_len - 4 - resultset_packet_length, num + 1);
            }
        }
    }
    return -1;
}

int ok_packet(char *payload, int payload_len) {

    /* TODO lcb*/
    /* packet length has parsed, so skip*/
    return payload[5];
}

int error_packet(char *payload, int payload_len) {
    return -1;
}

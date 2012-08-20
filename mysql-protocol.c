#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "mysql-protocol.h"

#define uint2korr(A)    (uint16) (((uint16) ((uchar) (A)[0])) +\
    ((uint16) ((uchar) (A)[1]) << 8))

#define uint3korr(A)    (uint32) (((uint32) ((uchar) (A)[0])) +\
    (((uint32) ((uchar) (A)[1])) << 8) +\
    (((uint32) ((uchar) (A)[2])) << 16))

#define uint4korr(A)    (uint32) (((uint32) ((uchar) (A)[0])) +\
    (((uint32) ((uchar) (A)[1])) << 8) +\
    (((uint32) ((uchar) (A)[2])) << 16) +\
    (((uint32) ((uchar) (A)[3])) << 24))

ulong error_packet(char *payload, int payload_len);
ulong ok_packet(char *payload, int payload_len);
ulong resultset_packet(char *payload, int payload_len, ulong num);
ulong eof_packet(char* payload, int payload_len);
ulong field_packet(char* payload, int payload_len, ulong field_number);

ulong net_field_length(char *packet);
ulong lcb_length(char *packet);

uchar *lastData;
size_t lastDataSize;
ulong lastNum;

int
parse_sql(char* payload, char** sql, int payload_len) {

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
ulong
parse_result(char* payload, int payload_len) {

    ulong ret;
    uchar *newData = NULL;

    if (lastData) {
        //printf("here\n");
        newData = malloc(payload_len + lastDataSize);
        memcpy(newData, lastData, lastDataSize);
        memcpy(newData + lastDataSize, payload, payload_len);
        free(lastData);
        lastData = NULL;

        ret = resultset_packet(newData, payload_len + lastDataSize, lastNum);

        free(newData); 
        newData = NULL;

        return ret;

    } else {
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
                    ulong field_number = net_field_length(payload + 4);
                    ulong field_lcb_length = lcb_length(payload + 4);
                    return field_packet(payload + 4 + field_lcb_length, 
                        payload_len - 4 - field_lcb_length, field_number);
                }
           }
        } 
        return -1;
    }
}

ulong
field_packet(char* payload, int payload_len, ulong field_number) {

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

ulong
eof_packet(char* payload, int payload_len) {

    if (payload_len > 4) {
        uchar c = payload[4]; 
        if (c == 0xfe) {
            return resultset_packet(payload + 4 + 5, payload_len - 4 - 5, 0); 
        }
    }
    return -1;
}

ulong
resultset_packet(char *payload, int payload_len, ulong num) {

    if (payload_len > 4) {
        int resultset_packet_length = uint3korr(payload);
        if (resultset_packet_length + 4 < payload_len) {
            /* resultset */
            return resultset_packet(payload + 4 + resultset_packet_length,
                payload_len - 4 - resultset_packet_length, num + 1);
        } else if (resultset_packet_length + 4 == payload_len) {
            uchar c = payload[4];
            if (c == 0xfe)
                return num;
        }
    }

    // mysql packets larger than a tcp packet
    // so need leave data next tcp packet
    //printf("last data is %d %d\n", payload_len, num);
    lastData = malloc(payload_len);
    memcpy(lastData, payload, payload_len);
    lastDataSize = payload_len;
    lastNum = num;
    return -2;
}

ulong 
ok_packet(char *payload, int payload_len) {

    /* packet length has parsed, so skip*/
    /* TODO no conclude len, possible codedump */
    return net_field_length(payload + 5);
}

ulong 
error_packet(char *payload, int payload_len) {
    return -1;
}

ulong 
net_field_length(char *packet) {

    uchar *pos= (uchar *)packet;

    if (*pos < 251) {
        return *pos;
    }
    if (*pos == 251) {
        return -1;
    }
    if (*pos == 252) {
        return (ulong) uint2korr(pos+1);
    }
    if (*pos == 253) {
        return (ulong) uint3korr(pos+1);
    }
    return (ulong) uint4korr(pos+1);
}

/* lcb length 1 3 4 9 */
ulong 
lcb_length(char *packet) {

    uchar *pos= (uchar *)packet;

    if (*pos < 251) {
        return 1;
    }
    if (*pos == 251) {
        (*packet)++;
        return -1;
    }
    if (*pos == 252) {
        return 3;
    }
    if (*pos == 253) {
        return 4;
    }
    return 9;
}


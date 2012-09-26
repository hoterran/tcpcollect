#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "mysqlpcap.h"
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

#define uint8korr(A)    ((ulonglong)(((uint32) ((uchar) (A)[0])) +\
    (((uint32) ((uchar) (A)[1])) << 8) +\
    (((uint32) ((uchar) (A)[2])) << 16) +\
    (((uint32) ((uchar) (A)[3])) << 24)) +\
    (((ulonglong) (((uint32) ((uchar) (A)[4])) +\
    (((uint32) ((uchar) (A)[5])) << 8) +\
    (((uint32) ((uchar) (A)[6])) << 16) +\
    (((uint32) ((uchar) (A)[7])) << 24))) <<\
    32))

#define int2store(T,A)       do { uint def_temp= (uint) (A) ;\
                                  *((uchar*) (T))=  (uchar)(def_temp); \
                                   *((uchar*) (T)+1)=(uchar)((def_temp >> 8)); \
                             } while(0)

#define int4store(T,A)       do { *((char *)(T))=(char) ((A));\
                                  *(((char *)(T))+1)=(char) (((A) >> 8));\
                                  *(((char *)(T))+2)=(char) (((A) >> 16));\
                                  *(((char *)(T))+3)=(char) (((A) >> 24)); } while(0)

#define int8store(T,A) do { uint def_temp= (uint) (A), def_temp2= (uint) ((A) >> 32); \
    int4store((T),def_temp); \
    int4store((T+4),def_temp2); } while(0)

#define memcpy_fixed(A,B,C) memcpy((A),(B),(C))

#define float4store(V,M) memcpy_fixed((uchar*) V,(uchar*) (&M),sizeof(float))

#define float8store(T,V) do { *(T)= ((uchar *) &V)[7];\
                              *((T)+1)=(char) ((uchar *) &V)[6];\
                              *((T)+2)=(char) ((uchar *) &V)[5];\
                              *((T)+3)=(char) ((uchar *) &V)[4];\
                              *((T)+4)=(char) ((uchar *) &V)[3];\
                              *((T)+5)=(char) ((uchar *) &V)[2];\
                              *((T)+6)=(char) ((uchar *) &V)[1];\
                              *((T)+7)=(char) ((uchar *) &V)[0]; } while(0)

ulong error_packet(char *payload, int payload_len);
ulong ok_packet(char *payload, int payload_len);
ulong resultset_packet(char *payload, int payload_len, ulong num);
ulong eof_packet(char* payload, int payload_len);
ulong field_packet(char* payload, int payload_len, ulong field_number);

ulong net_field_length(char *packet);
ulong lcb_length(char *packet);

uchar **lastData;
size_t *lastDataSize;
ulong *lastNum;

int
is_sql(char *payload, int payload_len, char **user) {

    /* 4 4 1 23[\0] n 2(min, without password) n */
    int packet_length = uint3korr(payload);

    if (payload_len >= packet_length + 4) {
        if (packet_length > 35) {
            if ((payload[13] == '\0') && (payload[35] == '\0')) {
                *user = payload + 36;
                return 0; // auth packet
            }
        } else {
            return 1; // COM_* Packet
        }
    }
    return -1; 
}

int
parse_sql(char* payload, char** sql, int payload_len) {

    /*3 1 1 sql */
    int packet_length = uint3korr(payload);
    
    if (payload_len >= packet_length + 4) {
        //TODO big sql, how to handle
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
parse_result(char* payload, int payload_len,
    uchar** myLastData, size_t *myLastDataSize, ulong *myLastNum) {

    ulong ret;
    char *newData = NULL;

    lastData = myLastData;
    lastDataSize = myLastDataSize;
    lastNum = myLastNum;

    if (lastData && *lastData) {
        //printf("here\n");
        newData = malloc(payload_len + *lastDataSize);
        memcpy(newData, *lastData, *lastDataSize);
        memcpy(newData + *lastDataSize, payload, payload_len);
        free(*lastData);
        *lastData = NULL;

        ret = resultset_packet(newData, payload_len + *lastDataSize, *lastNum);

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
    *lastData = malloc(payload_len);
    memcpy(*lastData, payload, payload_len);
    *lastDataSize = payload_len;
    *lastNum = num;
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
    return ERR;
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

static void store_param_null(char *buff) {            

    sprintf(buff + strlen(buff), "NULL, ");
}

static void store_param_tinyint(char *buff, char *param) {            

    char c = *(uchar *) param;
    sprintf(buff + strlen(buff), "%c, ", c);
}

static void store_param_short(char *buff, char *param) {           

    short value = *(short*) param;
    sprintf(buff + strlen(buff), "%hd, ", value);
}

static void store_param_int32(char *buff, char *param) {            

    int value = *(int*) param;
    sprintf(buff + strlen(buff), "%d, ", value);
}    

static void store_param_int64(char *buff, char *param) {    

    long value = *(long*) param;
    sprintf(buff + strlen(buff), "%ld, ", value);
}    

static void store_param_float(char *buff, char *param) {    

    float value = *(float*) param;
    sprintf(buff + strlen(buff), "%f, ", value);
}

static void store_param_double(char *buff, char *param) {   

    double value = *(double*) param;
    sprintf(buff + strlen(buff), "%lf, ", value);
}   

static int store_param_str(char *buff, char *param) {

    int length = net_field_length(param);
    int len = lcb_length(param);

    snprintf(buff + strlen(buff), length + 2 , "\"%s", param + len );
    snprintf(buff + strlen(buff), 3, "%s", "\",");
    return length + len;
}

/*
    libmysql:libmysql.c net_store_datetime
    1 is time lcb ,length is time length

    datetime = timestamp

    date is only 5bytes
*/

static int store_param_datetime(char* buffer, char *param) {

    char length = *param;
    assert((length == 11) || (length == 4));

    int year = uint2korr(param+1);

    if (length == 11) { 
        snprintf(buffer + strlen(buffer), 21,"%d-%d-%d %d:%d:%d,",
            year, *(param+3), *(param+4), 
            *(param+5), *(param+6), *(param+7));
    } else {
        snprintf(buffer + strlen(buffer), 12,"%d-%d-%d,",
            year, *(param+3), *(param+4));
    }

    return length + 1;
}

static int store_param_time(char* buffer, char *param) {

    char length = *param;

    assert(length == 12);

    int day = uint4korr(param+2); //skip length and neg

    snprintf(buffer + strlen(buffer), 15,"%d %d:%d:%d,",
        day, *(param+6), *(param+7), *(param+8));
    return length + 1;
}

int
parse_prepare_ok(char *payload, int payload_len, int *stmt_id, 
    short *param_count) {
    
    int packet_length = uint3korr(payload);
    int pos = 4;

    if (payload_len >= packet_length + 4) {
        pos++;          // skip ok
        *stmt_id = uint4korr(payload + pos);
        pos = pos + 4 + 2; // stmt_id, field_count
        *param_count = uint2korr(payload + pos); 
        return 0;
    }
    return -1;
}

int
parse_stmt_id(char *payload, int payload_len, int *stmt_id) {

    int packet_length = uint3korr(payload);
    int pos = 4;

    if (payload_len >= packet_length + 4) {
        pos++;          // skip ok
        *stmt_id = uint4korr(payload + pos);
        return 0;
    }
    return -1;
}
/*
    param_count conclude param_type size 

    param is output
*/

int 
parse_param(char *payload, int payload_len, int param_count, 
    char **param_type, char *param) {

    /* 
        COM_STMT_EXECUTE    1
        stmt_id             4
        flags               5
        null_count          1
        send_types_to_server    1

            type1               2
            type2               2
            typeN               2

        param1              N
        param2              N
        paramN              N
    */
    int packet_length = uint3korr(payload);
    int pos = 4;
    char *tmp_param_type;
    char *tmp_param = param;
    int ret = 0;
    int null_count_length = (param_count+7) / 8;
    char* null_pos = NULL;

    if (payload_len >= packet_length + 4) {
        pos++;  /*skip COM_STMT_EXECUTE */
        //int stmt_id = uint4korr(payload + pos);
        null_pos = payload + 5 + 4 + 5;
        pos = pos + 4 + 5 + null_count_length; /* stmt_id, flags, null_count */
        char send_types_to_server = payload[pos];
        pos++;

        if (send_types_to_server == 1) {
            /* here free old param_type, bad code*/
            //if (*param_type) {
             //   free(*param_type); 
            //}
            
            *param_type = payload + pos; 
            pos = pos + 2 * param_count; /* each type 2 bytes */
            ret = 1;
        }

        tmp_param_type = *param_type;

        int i = 0;
        short type;
        int length;

        for (;i < param_count; i++) {
            type = uint2korr(tmp_param_type);
            tmp_param_type = tmp_param_type + 2;

            // null 
            if(null_pos[i/8] & (1<<i)) {
                store_param_null(tmp_param);
                continue;
            }

            switch (type) {
                case MYSQL_TYPE_NULL:
                store_param_null(tmp_param);
                break;
            case MYSQL_TYPE_TINY:
                store_param_tinyint(tmp_param, payload + pos);
                pos++;
                break;                   
            case MYSQL_TYPE_SHORT:
                store_param_short(tmp_param, payload + pos);
                pos = pos + 2;
                break;                   
            case MYSQL_TYPE_LONG:
                store_param_int32(tmp_param, payload + pos);
                pos = pos + 4;
                break;
            case MYSQL_TYPE_LONGLONG:
                store_param_int64(tmp_param, payload + pos);
                pos = pos + 8;
                break;
            case MYSQL_TYPE_FLOAT:
                store_param_float(tmp_param, payload + pos);
                pos = pos + 4;
                break;
            case MYSQL_TYPE_DOUBLE:
                store_param_double(tmp_param, payload + pos);
                pos = pos + 8;
                break;
            case MYSQL_TYPE_TIME:
                length = store_param_time(tmp_param, payload + pos);
                pos = pos + length; 
                break;                       
            case MYSQL_TYPE_DATE:
            case MYSQL_TYPE_DATETIME:          
            case MYSQL_TYPE_TIMESTAMP:         
                length = store_param_datetime(tmp_param, payload + pos);
                pos = pos + length; 
                break;                       
            case MYSQL_TYPE_TINY_BLOB:         
            case MYSQL_TYPE_MEDIUM_BLOB:   
            case MYSQL_TYPE_LONG_BLOB:         
            case MYSQL_TYPE_BLOB:              
            case MYSQL_TYPE_VARCHAR:           
            case MYSQL_TYPE_VAR_STRING:    
            case MYSQL_TYPE_STRING:            
            case MYSQL_TYPE_DECIMAL:           
            case MYSQL_TYPE_NEWDECIMAL:    
                
                length = store_param_str(tmp_param, payload + pos);
                pos = pos + length;
            default:
                break;
            }
        }
        /*skip last ,*/
        tmp_param[strlen(tmp_param) - 1] = '\0';
        return ret;
    }
    return -1;
}

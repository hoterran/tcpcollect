#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "utils.h"
#include "log.h"
#include "mysqlpcap.h"
#include "protocol.h"
#include "packet.h"

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

ulong error_packet(char *payload, uint32 payload_len);
ulong ok_packet(char *payload, uint32 payload_len);
ulong resultset_packet(char *payload, uint32 payload_len, ulong num);
ulong eof_packet(char* payload, uint32 payload_len);
ulong field_packet(char* payload, uint32 payload_len, ulong field_number);

ulong net_field_length(char *packet);
ulong lcb_length(char *packet);

uchar **lastData;
size_t *lastDataSize;
ulong *lastNum;
enum ProtoStage *lastPs;

/*
 * sqlSaveLen == 0 call this function, verify it
 * is compress return OK, not return ERR
 * bad sql return BAD
*/
int isCompressPacket(char *payload, uint32 payload_len, int status)
{
    ASSERT(payload_len <= CAP_LEN);

    if (payload_len < 5) {
        dump(L_ERR, "what sql %u", payload_len);
        return BAD;
    }
    uchar c = payload[3];
    if (status != 0) {
        if (c != 0x00) {
            dump(L_ERR, "not first sql %u %c", payload_len, c);
            return BAD;
        }
    }

    uint32 packet_length = uint3korr(payload);

    /*
        normal
            payload_len <= packet_length + 4
        compress
            payload_len <= packet_length + 7
    */
    if (payload_len > packet_length + 4) {
        dump(L_ERR, "compress packet1 %u %u", payload_len, packet_length);
        ASSERT(payload_len <= packet_length + 7);
        return OK;
    }

    if (c == 0x01) {
        /* auth */
        return ERR;
    }

    int cmd = payload[4];
    if ((COM_QUIT <= cmd) && (cmd < COM_END)) {
        if (cmd == COM_QUIT) {
            if (payload_len != 5) {
                dump(L_OK, " compress sql2 ");
                return OK;
            }
        }
        /*
        if (((cmd != COM_STMT_CLOSE) && (cmd != COM_STMT_EXECUTE)
            && (cmd != COM_BINLOG_DUMP)
            && (cmd != COM_FIELD_LIST)
            ) && (status != AfterPreparePacket)
            && (payload_len > 7 ) && ( data[7] == '\0')) { //7 is compress length
            dump(L_OK, " compress sql3 ");
            return OK;
        }
        */
    } else {
        dump(L_OK, " compress sql4 ");
        return OK;
    }
    return ERR;
}
/*
    -1 auth
    -2 auth compress
    cmd cmd packet
    -3 bad data
*/
int
is_sql(char *payload, uint32 payload_len, char **user, char **db, uint32 sqlSaveLen) 
{
    ASSERT(payload_len <= CAP_LEN);
    ASSERT(sqlSaveLen == 0);

    if (payload_len < 5) {
        dump(L_ERR, "chao packets %u", payload_len);
        return -3; 
    } 
    int packet_length = uint3korr(payload);

    if (payload_len >= packet_length + 4) {
        /*
         *   4 4 1 23[\0] n 2(min, without password) n 
         *   how to difer sql packet and auth packet
        */
        if (packet_length > 35) {
            int i;
            for( i = 13; i <= 35; i++) {
                if (payload[i] != '\0') {
                    return payload[4]; 
                }
            }
            *user = payload + 36;
            // user length
            size_t l = strlen(payload + 36) + 1;
            ASSERT(l > 0);
            // salt and salt len
            
            int pwLen = lcb_length(payload + 36 + l) + net_field_length(payload + 36 + l);   

            if (payload_len == 36 + l + pwLen) {
                ASSERT(*db == NULL);
            } else {
                ASSERT(36 + l + pwLen < payload_len);
                // db just \0
                if (36 + l + pwLen + 1 == payload_len) {
                    *db = NULL; 
                } else {
                    *db = payload + 36 + l + pwLen; 
                }
            }

            #define CLIENT_COMPRESS     32  /* Can use compression protocol */ 
            unsigned long client_flag = 0;
            /* only 41 protocol */
            client_flag = uint4korr(payload + 4);
            if (client_flag & CLIENT_COMPRESS)
                return -2; //auth packet compress
            else 
                return -1; // auth packet
        } else {
            return payload[4]; // COM_* Packet
        }
    }
    return payload[4];  // big sql packet
}

int
parse_sql(char* payload, uint32 payload_len, char **sql, uint32 sqlSaveLen) 
{
    ASSERT(payload_len <= CAP_LEN);

    /* for big sql */
    if (sqlSaveLen > 0) {
        ASSERT(sqlSaveLen >= payload_len);
        return sqlSaveLen - payload_len;
    }

    /*3 1 1 sql */
    int packet_length = uint3korr(payload);

    if (payload_len >= packet_length + 4) {
        //mysql packet is complete
        payload[4 + packet_length] = '\0';
        *sql = &payload[5];
        return 0; // cmd
    }
    /* sql is too long, sqlSaveLen */
    payload[payload_len - 1] = '\0';
    *sql = &payload[5];
    return packet_length - (payload_len - 4);
}

/*
 *  0 ok
 *  -1 error
 *  -2 half resultset
 *  -3 secure compress packet
 *  -4 load data local file
 *  if a complete resultset size larger than tcp packet will failure
*/

long
parse_result(char* payload, uint32 payload_len,
    uchar** myLastData, size_t *myLastDataSize, ulong *myLastNum, enum ProtoStage *ps) 
{
    ASSERT(payload_len <= CAP_LEN);

    ulong ret;
    char *newData = NULL;

    lastData = myLastData;
    lastDataSize = myLastDataSize;
    lastNum = myLastNum;
    lastPs = ps;

    if (lastData && *lastData) {

        /*
        uchar *p; 
        int i = 0;
        for(p = *lastData; i<*lastDataSize; i++, p++) {
            //printf("\\x%02x %p\n", *p, p); 
        }   
        */

        ASSERT(*lastDataSize > 0);
        //printf("lastDataSize=%d lastData=%x \n", *lastDataSize, *myLastData);
        newData = malloc(payload_len + *lastDataSize);
        memcpy(newData, *lastData, *lastDataSize);
        memcpy(newData + *lastDataSize, payload, payload_len);
        free(*lastData);
        *lastData = NULL;

        if (*lastPs == RESULT_STAGE) {
            ret = resultset_packet(newData, payload_len + *lastDataSize, *lastNum);
        } else if (*lastPs == FIELD_STAGE) {
            ret = field_packet(newData, payload_len + *lastDataSize, *lastNum); 
        } else {
            ASSERT(*lastPs == EOF_STAGE);
            ret = eof_packet(newData, payload_len + *lastDataSize);
        }

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
                } else if (c == 0xfe) {
                    /* some COM return is eof, but never go here */
                    dump(L_OK, "secure-auth packet"); 
                    return -3;
                } else if (c == 0xfb) {
                    dump(L_OK, "load data local file"); 
                    return -4;
                } else {
                    /* resultset */
                    ulong field_number = net_field_length(payload + 4);
                    ASSERT(field_number < 500);
                    ulong field_lcb_length = lcb_length(payload + 4);
                    return field_packet(payload + 4 + field_lcb_length, 
                        payload_len - 4 - field_lcb_length, field_number);
                }
           }
        }
        dump(L_DEBUG, "%u", payload_len);
        ASSERT(NULL);
        return -2;
    }
}

ulong
field_packet(char* payload, uint32 payload_len, ulong field_number) 
{
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
    /* field packet span two packet */
    dump(L_DEBUG, "field span two packet");
    ASSERT(*lastData == NULL);
    *lastData = malloc(payload_len + 1);
    memcpy(*lastData, payload, payload_len);
    (*lastData)[payload_len] = 0;
    *lastDataSize = payload_len;
    *lastNum = field_number;
    *lastPs = FIELD_STAGE;
    return -2;
}

ulong
eof_packet(char* payload, uint32 payload_len) 
{
    ASSERT(payload_len <= CAP_LEN);

    if (payload_len > 4) {
        uchar c = payload[4];
        if (c == 0xfe) {
            if (payload_len > 9)
                return resultset_packet(payload + 4 + 5, payload_len - 4 - 5, 0);
        }
    }
    /* eof packet span two packet */
    dump(L_DEBUG, "eof span two packet %u\n", payload_len);
    ASSERT(*lastData == NULL);
    *lastData = malloc(payload_len + 1);
    memcpy(*lastData, payload, payload_len);
    (*lastData)[payload_len] = 0;
    *lastDataSize = payload_len;
    *lastPs = EOF_STAGE;
    return -2;
}

ulong
resultset_packet(char *payload, uint32 payload_len, ulong num) 
{
    int resultset_packet_length = 0;
    if (payload_len > 4) {
        resultset_packet_length = uint3korr(payload);
        if (resultset_packet_length + 4 < payload_len) {
            //printf("-------length %d number -------%d\n", resultset_packet_length, *(payload + 3));
            /* resultset */
            return resultset_packet(payload + 4 + resultset_packet_length,
                payload_len - 4 - resultset_packet_length, num + 1);
        } else if (resultset_packet_length + 4 == payload_len) {
            uchar c = payload[4];
            if (c == 0xfe)
                return num;
            else if (c == 0xff) /* after resultset, last packet can be error packet */
                return error_packet(payload, payload_len);
        }
    }

    // mysql packets larger than a tcp packet
    // so need leave data next tcp packet
    ASSERT(*lastData == NULL);
    *lastData = malloc(payload_len + 1);
    memcpy(*lastData, payload, payload_len);
    (*lastData)[payload_len] = 0;
    *lastDataSize = payload_len;
    *lastNum = num;
    *lastPs = RESULT_STAGE;

    /*
    uchar *p; 
    int i = 0;
    for(p = payload; i<payload_len; i++, p++) {
        //printf("\\x%02x %p\n", *p, p); 
    }   
    */

    //printf("lastDataSize=%ld currentNum=%ld resultsetLength=%d lastData=%x\n", 
     //   payload_len, num, resultset_packet_length, *lastData);
    return -2;
}

ulong 
ok_packet(char *payload, uint32 payload_len) {
    ASSERT(payload_len <= CAP_LEN);
    return net_field_length(payload + 5);
}

ulong 
error_packet(char *payload, uint32 payload_len) {
    ASSERT(payload_len <= CAP_LEN);
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

    sprintf(buff + strlen(buff), "NULL,");
}

static void store_param_tinyint(char *buff, char *param) {            

    sprintf(buff + strlen(buff), "%d,", param[0]);
}

static void store_param_short(char *buff, char *param) {           

    short value = *(short*) param;
    sprintf(buff + strlen(buff), "%hd,", value);
}

static void store_param_int32(char *buff, char *param) {            

    int value = *(int*) param;
    sprintf(buff + strlen(buff), "%d,", value);
}    

static void store_param_int64(char *buff, char *param) {    

    long value = *(long*) param;
    sprintf(buff + strlen(buff), "%ld,", value);
}    

static void store_param_float(char *buff, char *param) {    

    float value = *(float*) param;
    sprintf(buff + strlen(buff), "%f,", value);
}

static void store_param_double(char *buff, char *param) {   

    double value = *(double*) param;
    sprintf(buff + strlen(buff), "%lf,", value);
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


    11 bytes:
        year[2]
        month[1]
        day[1]
        hour[1]
        minute[1]
        second[1]
        second_part[4]
    7 bytes:
        year[2]
        month[1]
        day[1]
        hour[1]
        minute[1]
        second[1]
    4 bytes:
        year[2]
        month[1]
        day[1]
*/

static int store_param_datetime(char* buffer, char *param) {

    char length = *param;
    ASSERT((length == 11) || (length == 4) || (length == 7) || (length == 0));

    int year = uint2korr(param+1);
    int second_part ;

    if (length == 11) { 
        second_part = uint4korr(param + 8);
        /* TODO 30 is need modifed */
        snprintf(buffer + strlen(buffer), 30,"%d-%d-%d %d:%d:%d %d,",
            year, *(param+3), *(param+4), 
            *(param+5), *(param+6), *(param+7), second_part);
    } else if (length == 7) {
        snprintf(buffer + strlen(buffer), 21,"%d-%d-%d %d:%d:%d,",
            year, *(param+3), *(param+4), 
            *(param+5), *(param+6), *(param+7));
    } else if (length == 4) {
        snprintf(buffer + strlen(buffer), 12,"%d-%d-%d,",
            year, *(param+3), *(param+4));
    } else {
        snprintf(buffer + strlen(buffer), 3,"%s,", " ");
    }

    return length + 1;
}

/*
    12
        neg[1]
        day[4]
        hour[1]
        minute[1]
        second[1]
        second_part[4]
    8
        neg[1]
        day[4]
        hour[1]
        minute[1]
        second[1]

*/
static int 
store_param_time(char* buffer, char *param) {

    char length = *param;
    int day, second_part;

    ASSERT((length == 12) || (length == 8) || (length == 0));

    if (length == 12) {
        day = uint4korr(param+2); //skip length and neg
        second_part = uint4korr(param+9); 
        snprintf(buffer + strlen(buffer), 30,"%d %d:%d:%d %d,",
            day, *(param+6), *(param+7), *(param+8), second_part);
    } else if (length == 8) {
        day = uint4korr(param+2); //skip length and neg
        snprintf(buffer + strlen(buffer), 20,"%d %d:%d:%d,",
            day, *(param+6), *(param+7), *(param+8));
    } else {
        snprintf(buffer + strlen(buffer), 3,"%s,"," ");
    }
    return length + 1;
}

int
parse_prepare_ok(char *payload, uint32 payload_len, int *stmt_id, int *param_count) 
{
    ASSERT(payload_len <= CAP_LEN);

    /* 0x 0x 0x 01 00 */
    int packet_length = uint3korr(payload);
    int pos = 4;

    if (!((packet_length > 0) && (payload[4] == '\0') && (payload[3] == '\1'))){
        dump(L_ERR, "tail packet, ignore it");
        return -1;
    }
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
parse_stmt_id(char *payload, uint32 payload_len, int *stmt_id) 
{
    ASSERT(payload_len <= CAP_LEN);
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

char *
parse_param(char *payload, uint32 payload_len, int param_count, 
    char *param_type, char *param, size_t param_len) 
{
    ASSERT(payload_len <= CAP_LEN);
    int packet_length = uint3korr(payload);
    int pos = 4;
    char *param_type_pos = NULL;
    int null_count_length = (param_count+7) / 8;
    char* null_pos = NULL;
    const uint signed_bit = 1 << 15;

    if (payload_len >= packet_length + 4) {
        pos++;  /*skip COM_STMT_EXECUTE */
        //int stmt_id = uint4korr(payload + pos);
        null_pos = payload + 5 + 4 + 5;
        pos = pos + 4 + 5 + null_count_length; /* stmt_id, flags, null_count */
        char send_types_to_server = payload[pos];
        pos++;

        /* if =1 use below param_type, else use input param_type */
        if (send_types_to_server == 1) {
            param_type = param_type_pos  = payload + pos;
            pos = pos + 2 * param_count; /* each type 2 bytes */
        }

        int i = 0;
        short type;
        int length;

        for (;i < param_count; i++) {
            type = uint2korr(param_type) & ~signed_bit;
            param_type = param_type + 2;

            // null 
            if(null_pos[i/8] & (1 << (i & 7))) {
                store_param_null(param);
                continue;
            }
            
            // TODO use param_len 
            switch (type) {
                case MYSQL_TYPE_NULL:
                store_param_null(param);
                break;
            case MYSQL_TYPE_TINY:
                store_param_tinyint(param, payload + pos);
                pos++;
                break;                   
            case MYSQL_TYPE_SHORT:
                store_param_short(param, payload + pos);
                pos = pos + 2;
                break;                   
            case MYSQL_TYPE_LONG:
                store_param_int32(param, payload + pos);
                pos = pos + 4;
                break;
            case MYSQL_TYPE_LONGLONG:
                store_param_int64(param, payload + pos);
                pos = pos + 8;
                break;
            case MYSQL_TYPE_FLOAT:
                store_param_float(param, payload + pos);
                pos = pos + 4;
                break;
            case MYSQL_TYPE_DOUBLE:
                store_param_double(param, payload + pos);
                pos = pos + 8;
                break;
            case MYSQL_TYPE_TIME:
                length = store_param_time(param, payload + pos);
                pos = pos + length; 
                break;                       
            case MYSQL_TYPE_DATE:
            case MYSQL_TYPE_DATETIME:          
            case MYSQL_TYPE_TIMESTAMP:         
                length = store_param_datetime(param, payload + pos);
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
                
                length = store_param_str(param, payload + pos);
                pos = pos + length;
                break;
            default:
                break;
            }
        }
        /*skip last ,*/
        param[strlen(param) - 1] = '\0';
        return param_type_pos;
    }
    return NULL;
}

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#define _GNU_SOURCE
#include <string.h>

#include "utils.h"
#include "log.h"
#include "mysqlpcap.h"
#include "protocol.h"
#include "packet.h"
#include "stat.h"

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
 * is compress sql return OK, not return ERR
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
        if (!((c == 0x00) || (c == 0x01))) {
            dump(L_ERR, "not first sql %u %d", payload_len, c);
            printLastPacketInfo(1);
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
        if (payload_len > packet_length + 7) {
            dump(L_ERR,"why here2");
            printLastPacketInfo(1); 
        }
        //ASSERT(payload_len <= packet_length + 7); some strange will assert it
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
    uchar packet_number = payload[3];

    if (payload_len >= packet_length + 4) {
        /*
         *   4 4 1 23[\0] n 2(min, without password) n
         *   how to difer sql packet and auth packet
        */
        if ((packet_length > 35) && (packet_number == 0x01)) {
            int i;
            for( i = 13; i <= 35; i++) {
                if (payload[i] != '\0') {
                    // is sql
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
        //ASSERT(sqlSaveLen >= payload_len);
        if (sqlSaveLen < payload_len) {
            dump(L_ERR, "chao sql %u %u", sqlSaveLen, payload_len);
            return 0;
        }
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
        dump(L_DEBUG, "lastDataSize=%d lastData=%x \n", *lastDataSize, *myLastData);
        newData = malloc(payload_len + *lastDataSize);
        memcpy(newData, *lastData, *lastDataSize);
        memcpy(newData + *lastDataSize, payload, payload_len);
        free(*lastData);
        *lastData = NULL;
        uint32 new_len = payload_len + *lastDataSize;
        *lastDataSize = 0;
        ulong tempNum = *lastNum;
        *lastNum = 0;

        if (*lastPs == RESULT_STAGE) {
            ret = resultset_packet(newData, new_len, tempNum);
        } else if (*lastPs == FIELD_STAGE) {
            uchar c = newData[3];
            ret = field_packet(newData, new_len, tempNum);
        } else {
            uchar c = newData[3];
            ASSERT(*lastPs == EOF_STAGE);
            ret = eof_packet(newData, new_len);
        }

        free(newData);
        newData = NULL;

        return ret;
    } else {
        /*header*/
        int header_packet_length = 0;
        uchar c = 0;
        if (payload_len < 5) {
            dump(L_ERR, "chao result packet %u", payload_len);
            return  -2;
        }
        if (payload_len > 4) {
            header_packet_length = uint3korr(payload);

           if (header_packet_length + 4 <= payload_len) {
                c = payload[4];
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
                    /* here possible headshake packet or bad packet */
                    if (header_packet_length > 0 && header_packet_length < 10) {
                        ulong field_lcb_length = lcb_length(payload + 4); 
                        ulong field_number = net_field_length(payload + 4); 
                        /*is def, seq must increment ?*/
                        if ((header_packet_length == field_lcb_length) &&
                            (field_lcb_length < 4) && (field_number < 500)) {
                            int header_seq = payload[3];
                            int field_seq = payload[3 + header_packet_length + 4]; 
                            int defPos = 4 + header_packet_length + 4;
                            char *def = strndup(payload + defPos + 1 ,3);
                            if  ((0x03 == payload[defPos]) &&
                                (0 == strncmp(def, "def", 3) &&
                                (header_seq + 1 == field_seq)
                                )) {
                                free(def);
                                return field_packet(payload + 4 + field_lcb_length,
                                    payload_len - 4 - field_lcb_length, field_number);
                            }   
                            free(def);
                        }   
                    }
                }
            }
        }
        dump(L_ERR,"why here");
        printLastPacketInfo(1);
        return -2;
    }
}

ulong
field_packet(char* payload, uint32 payload_len, ulong field_number)
{
    int field_packet_length = 0;

    if (payload_len > 4) {
            field_packet_length = uint3korr(payload);
            /* dont care content, so skip it */
            if (field_packet_length + 4 < payload_len) {
                return field_packet(payload + 4 + field_packet_length,
                    payload_len - 4 - field_packet_length, field_number - 1);
            }
    }

    /* field packet span two packet */
    dump(L_DEBUG, "field span two packet %u %d", payload_len, field_packet_length);
    ASSERT(*lastData == NULL);
    *lastData = malloc(payload_len + 1);
    memcpy(*lastData, payload, payload_len);
    (*lastData)[payload_len] = 0;
    *lastDataSize = payload_len;
    //ASSERT(*lastDataSize < 10000);
    *lastNum = field_number;
    *lastPs = FIELD_STAGE;
    if(payload_len < 200) return 0;
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
    dump(L_DEBUG, "eof span two packet %u", payload_len);
    ASSERT(payload_len < 10);
    ASSERT(*lastData == NULL);
    ASSERT(*lastDataSize == 0);
    ASSERT(*lastNum == 0);
    *lastData = malloc(payload_len + 1);
    memcpy(*lastData, payload, payload_len);
    (*lastData)[payload_len] = 0;
    *lastDataSize = payload_len;
    ASSERT(*lastDataSize < 10000);
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
parse_prepare_ok(char *payload, uint32 payload_len, ulong *stmt_id, int *param_count)
{
    ASSERT(payload_len <= CAP_LEN);

    /* 0x 0x 0x 01 00 */
    int packet_length = uint3korr(payload);
    int pos = 4;

    if (!((packet_length > 0) && (payload[4] == '\0') && (payload[3] == '\1') && (payload[13] == '\0'))){
        dump(L_DEBUG, "tail packet, ignore it");
        return -1;
    }
    if (!((packet_length == 10) || (packet_length == 12))) {
        dump(L_DEBUG, "tail packet, ignore it2 ");
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
parse_stmt_id(char *payload, uint32 payload_len, ulong *stmt_id)
{
    ASSERT(payload_len <= CAP_LEN);
    int packet_length = uint3korr(payload);
    int pos = 4;

    if (payload_len < 14) {
        dump(L_ERR, "not execute packet %u", payload_len); 
        return ERR;
    }
    ulong count = uint4korr(payload + 10);
    if (count != 1) {
        dump(L_ERR, "execute count is %u error ", count); 
        return ERR;
    }
    if (payload_len >= packet_length + 4) {
        pos++;          // skip ok
        *stmt_id = uint4korr(payload + pos);
        return 0;
    }
    return ERR;
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

int check_param_type (char *param_type, int param_count) {
    short type;
    const uint signed_bit = 1 << 15;
    int i = 0;
    for (;i < param_count; i++) {
        type = uint2korr(param_type) & ~signed_bit;
        param_type = param_type + 2;
	ASSERT((type <= MYSQL_TYPE_GEOMETRY) && (type >= MYSQL_TYPE_DECIMAL));
    }
    return 0;
}

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

	//possible without send_types_to_server
	if (pos + 1 > payload_len) {
            dump(L_ERR, "parse_param failure2 %d %u", pos, payload_len);
            return NULL;
        }
	
        /* if =1 use below param_type, else use input param_type */
	ASSERT((send_types_to_server == 1 ) || (send_types_to_server == 0));
        if (send_types_to_server == 1) {
            param_type = param_type_pos  = payload + pos;
            pos = pos + 2 * param_count; /* each type 2 bytes */
        }
	if (!param_type) {
		dump(L_ERR, "why here3");
		printLastPacketInfo(10);
		return NULL;	
	}
        int i = 0;
        short type;
        int length;

        for (;i < param_count; i++) {
            type = uint2korr(param_type) & ~signed_bit;
            param_type = param_type + 2;

            if ((pos > payload_len) || (
                type > MYSQL_TYPE_GEOMETRY)) {
                dump(L_ERR, "parse_param failure %d %u, %d",
                    pos, payload_len ,type);
                break;
            }

            /* skip null */
            if(null_pos[i/8] & (1 << (i & 7))) {
                store_param_null(param);
                continue;
            }

            /* param_len possible short than param in payload
             * how to deal?
            */
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
		ASSERT(NULL);
                break;
            }
        }
        /*skip last ,*/
        param[strlen(param) - 1] = '\0';
        return param_type_pos;
    }
    return NULL;
}

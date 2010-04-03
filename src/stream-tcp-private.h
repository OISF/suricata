#ifndef __STREAM_TCP_PRIVATE_H__
#define __STREAM_TCP_PRIVATE_H__

#include "decode.h"
typedef struct TcpSegment_ {
    uint8_t *payload;
    uint16_t payload_len; /* actual size of the payload */
    uint32_t seq;
    uint16_t pool_size; /* size of the memory */
    uint8_t flags;
    struct TcpSegment_ *next;
    struct TcpSegment_ *prev;
} TcpSegment;

typedef struct TcpStream_ {
    uint32_t isn;       /**< initial sequence number */
    uint32_t next_seq;  /**< next expected sequence number */
    uint32_t last_ack;  /**< last ack'd sequence number in this stream */
    uint32_t next_win;  /**< next max seq within window */
    uint32_t window;    /**< current window setting */
    uint8_t wscale;     /**< wscale setting in this direction */

    uint32_t last_ts; /**< Time stamp (TSVAL) of the last seen packet for this stream*/
    uint32_t last_pkt_ts; /**< Time of last seen packet for this stream (needed for PAWS update)
                                This will be used to validate the last_ts, when connection has been idle for
                                longer time.(RFC 1323)*/

    /* reassembly */
    uint32_t ra_base_seq; /**< reassembled seq. We've reassembled up to this point. */
    TcpSegment *seg_list; /**< list of TCP segments that are not yet (fully) used in reassembly */
    uint8_t os_policy; /**< target based OS policy used for reassembly and handling packets*/
    uint16_t flags;      /**< Flag specific to the stream e.g. Timestamp */
    TcpSegment *seg_list_tail;  /**< Last segment in the reassembled stream seg list*/
    uint32_t tmp_ra_base_seq;   /**< Temporary reassembled seq, to be used until
                                     app layer protocol has not been detected,
                                     beacuse every smsg needs to contain all the
                                     initial segments too */
} TcpStream;

/* from /usr/include/netinet/tcp.h */
enum
{
    TCP_NONE,
    TCP_LISTEN,
    TCP_SYN_SENT,
    TCP_SYN_RECV,
    TCP_ESTABLISHED,
    TCP_FIN_WAIT1,
    TCP_FIN_WAIT2,
    TCP_TIME_WAIT,
    TCP_LAST_ACK,
    TCP_CLOSE_WAIT,
    TCP_CLOSING,
    TCP_CLOSED,
};

#define STREAMTCP_FLAG_MIDSTREAM                0x0001  /**< Flag for mid stream
                                                             session*/
#define STREAMTCP_FLAG_MIDSTREAM_ESTABLISHED    0x0002  /**< Flag for mid stream
                                                             established
                                                             session*/
#define STREAMTCP_FLAG_MIDSTREAM_SYNACK         0x0004  /**< Flag for mid session
                                                             when syn/ack is
                                                             received*/
#define STREAMTCP_FLAG_TIMESTAMP                0x0008  /**< Flag for TCP
                                                             Timestamp option*/
#define STREAMTCP_FLAG_SERVER_WSCALE            0x0010  /**< Server supports
                                                             wscale (even though
                                                             it can be 0) */
#define STREAMTCP_FLAG_ZERO_TIMESTAMP           0x0020  /**< Flag to indicate the
                                                             zero value of
                                                             timestamp*/
#define STREAMTCP_FLAG_NOCLIENT_REASSEMBLY      0x0040  /**< Flag to avoid stream
                                                             reassembly/app layer
                                                             inspection for the
                                                             client stream.*/
#define STREAMTCP_FLAG_NOSERVER_REASSEMBLY      0x0080  /**< Flag to avoid stream
                                                             reassembly / app layer
                                                             inspection for the
                                                             server stream.*/
#define STREAMTCP_FLAG_ASYNC                    0x0100  /**< Flag to indicate
                                                             that the session is
                                                             handling asynchronous
                                                             stream.*/
#define STREAMTCP_FLAG_4WHS                     0x0200  /**< Flag to indicate
                                                             we're dealing with
                                                             4WHS: SYN, SYN,
                                                             SYN/ACK, ACK
 (http://www.breakingpointsystems.com/community/blog/tcp-portals-the-three-way-handshake-is-a-lie) */

#define STREAMTCP_FLAG_APPPROTO_DETECTION_COMPLETED 0x0400  /**< Flag to indicate
                                                             the app layer has
                                                             detected the app
                                                             layer protocol on
                                                             the current
                                                             TCP session */
#define STREAMTCP_FLAG_PAUSE_TOSERVER_REASSEMBLY 0x0800 /**< Flag to pause stream
                                                             reassembly / app layer
                                                             inspection for the
                                                             server stream.*/
#define STREAMTCP_FLAG_PAUSE_TOCLIENT_REASSEMBLY 0x1000 /**< Flag to pause stream
                                                             reassembly / app layer
                                                             inspection for the
                                                             client stream.*/

#define SEGMENTTCP_FLAG_PROCESSED               0x01    /**< Flag to indicate
                                                             that the current
                                                             segment has been
                                                             processed by the
                                                             reassembly code and
                                                             should be deleted
                                                             after app layer
                                                             protocol has been
                                                             detected. */

#define PAWS_24DAYS         2073600         /**< 24 days in seconds */

#define PKT_IS_IN_RIGHT_DIR(ssn, p)        ((ssn)->flags & STREAMTCP_FLAG_MIDSTREAM_SYNACK ? \
                                            PKT_IS_TOSERVER(p) ? (p)->flowflags &= ~FLOW_PKT_TOSERVER \
                                            (p)->flowflags |= FLOW_PKT_TOCLIENT : (p)->flowflags &= ~FLOW_PKT_TOCLIENT \
                                            (p)->flowflags |= FLOW_PKT_TOSERVER : 0)

/* Macro's for comparing Sequence numbers
 * Page 810 from TCP/IP Illustrated, Volume 2. */
#define SEQ_EQ(a,b)  ((int32_t)((a) - (b)) == 0)
#define SEQ_LT(a,b)  ((int32_t)((a) - (b)) <  0)
#define SEQ_LEQ(a,b) ((int32_t)((a) - (b)) <= 0)
#define SEQ_GT(a,b)  ((int32_t)((a) - (b)) >  0)
#define SEQ_GEQ(a,b) ((int32_t)((a) - (b)) >= 0)

typedef struct TcpSession_ {
    uint8_t state;
    uint16_t flags;
    uint16_t alproto; /**< application level protocol */
    TcpStream server;
    TcpStream client;
    void **aldata; /**< application level storage ptrs */
} TcpSession;

#endif /* __STREAM_TCP_PRIVATE_H__ */


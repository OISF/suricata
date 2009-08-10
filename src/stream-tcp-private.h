#ifndef __STREAM_TCP_PRIVATE_H__
#define __STREAM_TCP_PRIVATE_H__

typedef struct TcpSegment_ {
    uint8_t *payload;
    uint16_t payload_len; /* actual size of the payload */
    uint32_t seq;
    uint16_t pool_size; /* size of the memory */
    struct TcpSegment_ *next;
    struct TcpSegment_ *prev;
} TcpSegment;

typedef struct TcpStream_ {
    uint32_t isn; /* initial sequence number */
    uint32_t next_seq; /* next expected sequence number */
    uint32_t last_ack; /* last ack'd sequence number */
    uint32_t next_win; /* next max seq within window */
    uint8_t wscale;
    uint16_t window;

    /* reassembly */
    uint32_t ra_base_seq; /* reassembled seq. We've reassembled up to this point. */
    TcpSegment *seg_list;
    uint8_t os_policy; /* target based OS policy used for reassembly and handling packets*/
} TcpStream;

/* from /usr/include/netinet/tcp.h */
enum
{
    TCP_ESTABLISHED = 1,
    TCP_SYN_SENT,
    TCP_SYN_RECV,
    TCP_FIN_WAIT1,
    TCP_FIN_WAIT2,
    TCP_TIME_WAIT,
    TCP_CLOSED,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    TCP_LISTEN,
    TCP_CLOSING   /* now a valid state */
};

#define STREAMTCP_FLAG_MIDSTREAM                0x01    /*Flag for mid stream session*/
#define STREAMTCP_FLAG_MIDSTREAM_ESTABLISHED    0x02    /*Flag for mid stream established session*/

/* Macro's for comparing Sequence numbers
 * Page 810 from TCP/IP Illustrated, Volume 2. */
#define SEQ_EQ(a,b)  ((int)((a) - (b)) == 0)
#define SEQ_LT(a,b)  ((int)((a) - (b)) <  0)
#define SEQ_LEQ(a,b) ((int)((a) - (b)) <= 0)
#define SEQ_GT(a,b)  ((int)((a) - (b)) >  0)
#define SEQ_GEQ(a,b) ((int)((a) - (b)) >= 0)

typedef struct TcpSession_ {
    uint8_t state;
    TcpStream server;
    TcpStream client;
    void **l7data;
    u_int8_t flags;
} TcpSession;
#endif /* __STREAM_TCP_PRIVATE_H__ */

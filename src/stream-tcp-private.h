#ifndef __STREAM_TCP_PRIVATE_H__
#define __STREAM_TCP_PRIVATE_H__

typedef struct TcpSegment_ {
    u_int8_t *payload;
    u_int16_t payload_len; /* actual size of the payload */
    u_int32_t seq;
    u_int16_t pool_size; /* size of the memory */
    struct TcpSegment_ *next;
    struct TcpSegment_ *prev;
} TcpSegment;

typedef struct TcpStream_ {
    u_int32_t isn; /* initial sequence number */
    u_int32_t next_seq; /* next expected sequence number */
    u_int32_t last_ack; /* last ack'd sequence number */
    u_int32_t next_win; /* next max seq within window */
    u_int8_t wscale;
    u_int16_t window;

    /* reassembly */
    u_int32_t ra_base_seq; /* reassembled seq. We've reassembled up to this point. */
    TcpSegment *seg_list;
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
    TCP_CLOSE,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    TCP_LISTEN,
    TCP_CLOSING   /* now a valid state */
};

/* Macro's for comparing Sequence numbers
 * Page 810 from TCP/IP Illustrated, Volume 2. */
#define SEQ_EQ(a,b)  ((int)((a) - (b)) == 0)
#define SEQ_LT(a,b)  ((int)((a) - (b)) <  0)
#define SEQ_LEQ(a,b) ((int)((a) - (b)) <= 0)
#define SEQ_GT(a,b)  ((int)((a) - (b)) >  0)
#define SEQ_GEQ(a,b) ((int)((a) - (b)) >= 0)

typedef struct TcpSession_ {
    u_int8_t state;
    TcpStream server;
    TcpStream client;
    void **l7data;
} TcpSession;

#endif /* __STREAM_TCP_PRIVATE_H__ */

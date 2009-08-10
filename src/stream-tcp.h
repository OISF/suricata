/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __STREAM_TCP_H__
#define __STREAM_TCP_H__

#define COUNTER_STREAMTCP_STREAMS 1

#define STREAM_VERBOSE    FALSE
/*global flow data*/
typedef struct TcpStreamCnf_ {
    u_int32_t max_sessions;
    u_int32_t prealloc_sessions;
    u_int8_t midstream;
} TcpStreamCnf;

TcpStreamCnf stream_config;
void TmModuleStreamTcpRegister (void);
void StreamTcpInitConfig (char);

#endif /* __STREAM_TCP_H__ */


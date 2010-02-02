/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __STREAM_TCP_H__
#define __STREAM_TCP_H__

#define COUNTER_STREAMTCP_STREAMS 1

#define STREAM_VERBOSE    FALSE
/*global flow data*/
typedef struct TcpStreamCnf_ {
    uint32_t memcap; /** max stream mem usage */
    int max_sessions;
    int prealloc_sessions;
    int midstream;
    int async_oneside;
} TcpStreamCnf;

TcpStreamCnf stream_config;
void TmModuleStreamTcpRegister (void);
void StreamTcpInitConfig (char);
void StreamTcpFreeConfig(char);
void StreamTcpRegisterTests (void);

void StreamTcpIncrMemuse(uint32_t);
void StreamTcpDecrMemuse(uint32_t);
int StreamTcpCheckMemcap(uint32_t);

#endif /* __STREAM_TCP_H__ */


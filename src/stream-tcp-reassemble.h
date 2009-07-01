/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __STREAM_TCP_REASSEMBLE_H__
#define __STREAM_TCP_REASSEMBLE_H__

int StreamTcpReassembleHandleSegment (TcpSession *ssn, TcpStream *stream, Packet *p);
int StreamTcpReassembleInit(void);

#endif /* __STREAM_TCP_REASSEMBLE_H__ */


/** Copyright (c) 2008 Victor Julien <victor@inliniac.net>
 *  Copyright (c) 2009 Open Information Security Foundation
 *
 *  \author Victor Julien <victor@inliniac.net>
 *  \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 */

#ifndef __STREAM_TCP_REASSEMBLE_H__
#define __STREAM_TCP_REASSEMBLE_H__

#include "stream.h"

/** Supported OS list and default OS policy is BSD */
enum
{
    OS_POLICY_NONE = 0,
    OS_POLICY_BSD,
    OS_POLICY_OLD_LINUX,
    OS_POLICY_LINUX,
    OS_POLICY_SOLARIS,
    OS_POLICY_HPUX10,
    OS_POLICY_HPUX11,
    OS_POLICY_IRIX,
    OS_POLICY_MACOS,
    OS_POLICY_WINDOWS,
    OS_POLICY_VISTA,
    OS_POLICY_WINDOWS2K3,
    OS_POLICY_FIRST,
    OS_POLICY_LAST
};

typedef struct TcpReassemblyThreadCtx_ {
    StreamMsgQueue *stream_q;
} TcpReassemblyThreadCtx;

#define OS_POLICY_DEFAULT   OS_POLICY_BSD

int StreamTcpReassembleHandleSegment(TcpReassemblyThreadCtx *, TcpSession *, TcpStream *, Packet *);
int StreamTcpReassembleInit(char);
void StreamTcpReassembleFree(char);
void StreamTcpReassembleRegisterTests(void);

TcpReassemblyThreadCtx *StreamTcpReassembleInitThreadCtx(void);
int StreamTcpReassembleProcessAppLayer(TcpReassemblyThreadCtx *);

void StreamTcpCreateTestPacket(u_int8_t *, u_int8_t, u_int8_t);

void StreamL7DataPtrInit(TcpSession *ssn, uint8_t cnt);

void StreamTcpSetSessionNoReassemblyFlag (TcpSession *, char );

#endif /* __STREAM_TCP_REASSEMBLE_H__ */


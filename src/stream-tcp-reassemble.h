/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */
/*  2009 Gurvinder Singh <gurvindersinghdahiya@gmail.com>*/

#ifndef __STREAM_TCP_REASSEMBLE_H__
#define __STREAM_TCP_REASSEMBLE_H__
/*Supported OS list and default OS policy is BSD*/
enum
{
 OS_POLICY_BSD = 1,
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

#define OS_POLICY_DEFAULT   OS_POLICY_BSD

int StreamTcpReassembleHandleSegment (TcpSession *ssn, TcpStream *stream, Packet *p);
int StreamTcpReassembleInit(void);
void SreamTcpReassembleRegisterTests (void);

#endif /* __STREAM_TCP_REASSEMBLE_H__ */


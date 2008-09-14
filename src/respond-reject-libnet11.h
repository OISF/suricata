/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __RESPOND_REJECT_LIBNET11_H__
#define __RESPOND_REJECT_LIBNET11_H__

int RejectSendLibnet11L3IPv4TCP(ThreadVars *, Packet *, void *,int);
int RejectSendLibnet11L3IPv4ICMP(ThreadVars *, Packet *, void *,int);
#endif /* __RESPOND_REJECT_LIBNET11_H__ */

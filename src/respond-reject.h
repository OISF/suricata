/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __RESPOND_REJECT_H__
#define __RESPOND_REJECT_H__

#define REJECT_DIR_SRC 0
#define REJECT_DIR_DST 1

void TmModuleRespondRejectRegister (void);
TmEcode RespondRejectFunc(ThreadVars *, Packet *, void *, PacketQueue *);

#endif /* __RESPOND_REJECT_H__ */

/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */
#ifndef __PKT_VAR_H__
#define __PKT_VAR_H__

void PktVarAdd(Packet *, char *, uint8_t *, uint16_t);
PktVar *PktVarGet(Packet *, char *);
void PktVarFree(PktVar *);
void PktVarPrint(PktVar *);

#endif /* __PKT_VAR_H__ */


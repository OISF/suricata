/* Copyright (c) 2009 Open Information Security Foundation */

/**
 * \file
 *
 * Defragmentation module.
 *
 * \author Endace Technology Limited, Jason Ish <jason.ish@endace.com>
 */

#ifndef __DEFRAG_H__
#define __DEFRAG_H__

typedef struct _DefragContext DefragContext;

void DefragInit(void);
Packet *Defrag4(ThreadVars *, DefragContext *, Packet *);
Packet *Defrag6(ThreadVars *, DefragContext *, Packet *);
void DefragRegisterTests(void);

#endif /* __DEFRAG_H__ */

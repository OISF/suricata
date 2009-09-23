/* Copyright (c) 2009 Victor Julien <victor@inliniac.net> */

#ifndef __SOURCE_PFRING_H__
#define __SOURCE_PFRING_H__

void TmModuleReceivePfringRegister (void);
void TmModuleDecodePfringRegister (void);

/* XXX replace with user configurable options */
#define LIBPFRING_SNAPLEN     1518
#define LIBPFRING_PROMISC     1
#define LIBPFRING_REENTRANT   0
#define LIBPFRING_WAIT_FOR_INCOMING 1
#endif /* __SOURCE_PFRING_H__ */

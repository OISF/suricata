/* Copyright (c) 2008 Victor Julien <victor@inliniac.net> */

#ifndef __SOURCE_NFQ_PROTOTYPES_H__
#define __SOURCE_NFQ_PROTOTYPES_H__

int NFQInitThread(ThreadVars *, NFQThreadVars *, u_int16_t, u_int32_t);

void TmModuleReceiveNFQRegister (void);
void TmModuleVerdictNFQRegister (void);
void TmModuleDecodeNFQRegister (void);


#endif /* __SOURCE_NFQ_PROTOTYPES_H__ */

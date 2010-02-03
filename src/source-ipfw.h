/* Copyright (c) 2009 Open Information Security Foundation */

/** \file
 *  \author Nick Rogness <nick@rogness.net>
 */

#ifndef __SOURCE_IPFW_H__
#define __SOURCE_IPFW_H__

#include <pthread.h>


/* per packet IPFW vars (Not used) */
typedef struct IPFWPacketVars_
{
} IPFWPacketVars;

void TmModuleReceiveIPFWRegister (void);
void TmModuleVerdictIPFWRegister (void);
void TmModuleDecodeIPFWRegister (void);

#endif /* __SOURCE_IPFW_H__ */

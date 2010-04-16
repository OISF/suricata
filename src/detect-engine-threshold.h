/* Copyright (c) 2009 Open Information Security Foundation */

/** \file
 *  \author Breno Silva <breno.silva@gmail.com>
 */


#ifndef __DETECT_ENGINE_THRESHOLD_H__
#define __DETECT_ENGINE_THRESHOLD_H__

#include "detect.h"

#define THRESHOLD_HASH_SIZE 0xffff

void PacketAlertHandle(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *,
                       Signature *sig, Packet *p);
DetectThresholdData *SigGetThresholdType(Signature *, Packet *);
void PacketAlertThreshold(DetectEngineCtx *, DetectEngineThreadCtx *,
                          DetectThresholdData *, Packet *, Signature *);
void ThresholdFreeFunc(void *data);
char ThresholdCompareFunc(void *data1, uint16_t len1, void *data2,uint16_t len2);
uint32_t ThresholdHashFunc(HashListTable *ht, void *data, uint16_t datalen);
void ThresholdHashInit(DetectEngineCtx *de_ctx);
void ThresholdTimeoutRemove(DetectEngineCtx *de_ctx);
void ThresholdContextDestroy(DetectEngineCtx *de_ctx);

#endif /* __DETECT_ENGINE_THRESHOLD_H__ */

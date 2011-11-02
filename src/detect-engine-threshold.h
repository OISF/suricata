/* Copyright (C) 2007-2010 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/**
 * \file
 *
 *  \author Breno Silva <breno.silva@gmail.com>
 *  \author Victor Julien <victor@inliniac.net>
 */

#ifndef __DETECT_ENGINE_THRESHOLD_H__
#define __DETECT_ENGINE_THRESHOLD_H__

#include "detect.h"

#define THRESHOLD_HASH_SIZE 0xffff

DetectThresholdData *SigGetThresholdType(Signature *, Packet *);
DetectThresholdData *SigGetThresholdTypeIter(Signature *sig, Packet *p, SigMatch **psm);
int PacketAlertThreshold(DetectEngineCtx *, DetectEngineThreadCtx *,
                          DetectThresholdData *, Packet *, Signature *);
void ThresholdFreeFunc(void *data);
char ThresholdCompareFunc(void *data1, uint16_t len1, void *data2,uint16_t len2);
uint32_t ThresholdHashFunc(HashListTable *ht, void *data, uint16_t datalen);
void ThresholdHashInit(DetectEngineCtx *de_ctx);
void ThresholdContextDestroy(DetectEngineCtx *de_ctx);

#endif /* __DETECT_ENGINE_THRESHOLD_H__ */

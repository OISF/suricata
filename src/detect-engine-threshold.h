/* Copyright (C) 2007-2022 Open Information Security Foundation
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
#include "host.h"
#include "ippair.h"
#include "host-storage.h"

void ThresholdInit(void);

HostStorageId ThresholdHostStorageId(void);
int ThresholdHostHasThreshold(Host *);

int ThresholdIPPairHasThreshold(IPPair *pair);

const DetectThresholdData *SigGetThresholdTypeIter(
        const Signature *, const SigMatchData **, int list);
int PacketAlertThreshold(DetectEngineCtx *, DetectEngineThreadCtx *,
        const DetectThresholdData *, Packet *,
        const Signature *, PacketAlert *);

void ThresholdHashInit(DetectEngineCtx *);
void ThresholdHashAllocate(DetectEngineCtx *);
void ThresholdContextDestroy(DetectEngineCtx *);

int ThresholdHostTimeoutCheck(Host *, struct timeval *);
int ThresholdIPPairTimeoutCheck(IPPair *, struct timeval *);
void ThresholdListFree(void *ptr);

#endif /* __DETECT_ENGINE_THRESHOLD_H__ */

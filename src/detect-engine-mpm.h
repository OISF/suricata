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
 * \author Victor Julien <victor@inliniac.net>
 */

#ifndef __DETECT_ENGINE_MPM_H__
#define __DETECT_ENGINE_MPM_H__

#include "tm-modules.h"

uint16_t PatternMatchDefaultMatcher(void);

uint32_t PacketPatternSearch(ThreadVars *, DetectEngineThreadCtx *, Packet *);
uint32_t UriPatternSearch(ThreadVars *, DetectEngineThreadCtx *, uint8_t *, uint16_t);

void PacketPatternCleanup(ThreadVars *, DetectEngineThreadCtx *);

void PatternMatchPrepare(MpmCtx *, uint16_t);
void PatternMatchThreadPrepare(MpmThreadCtx *, uint16_t type, uint32_t max_id);

void PatternMatchDestroy(MpmCtx *, uint16_t);
void PatternMatchThreadDestroy(MpmThreadCtx *mpm_thread_ctx, uint16_t);
void PatternMatchThreadPrint(MpmThreadCtx *, uint16_t);

int PatternMatchPrepareGroup(DetectEngineCtx *, SigGroupHead *);
void DetectEngineThreadCtxInfo(ThreadVars *, DetectEngineThreadCtx *);
void PatternMatchDestroyGroup(SigGroupHead *);

TmEcode DetectEngineThreadCtxInit(ThreadVars *, void *, void **);
TmEcode DetectEngineThreadCtxDeinit(ThreadVars *, void *);

void DbgPrintSearchStats();

#endif /* __DETECT_ENGINE_MPM_H__ */


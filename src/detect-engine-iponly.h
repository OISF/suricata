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

#ifndef __DETECT_ENGINE_IPONLY_H__
#define __DETECT_ENGINE_IPONLY_H__

/**
 * SigNumArray is a bit array representing signatures
 * it can be used linked to src/dst address to indicate
 * which signatures apply to this addres
 * at IP Only we store SigNumArrays at the radix trees
 */
typedef struct SigNumArray_ {
    uint8_t *array; /* bit array of sig nums */
    uint32_t size;  /* size in bytes of the array */
} SigNumArray;

void IPOnlyCIDRListFree(IPOnlyCIDRItem *tmphead);
int IPOnlySigParseAddress(const DetectEngineCtx *, Signature *, const char *, char);
void IPOnlyMatchPacket(ThreadVars *tv, DetectEngineCtx *,
                       DetectEngineThreadCtx *, DetectEngineIPOnlyCtx *,
                       DetectEngineIPOnlyThreadCtx *, Packet *);
void IPOnlyInit(DetectEngineCtx *, DetectEngineIPOnlyCtx *);
void IPOnlyPrint(DetectEngineCtx *, DetectEngineIPOnlyCtx *);
void IPOnlyDeinit(DetectEngineCtx *, DetectEngineIPOnlyCtx *);
void IPOnlyPrepare(DetectEngineCtx *);
void DetectEngineIPOnlyThreadInit(DetectEngineCtx *, DetectEngineIPOnlyThreadCtx *);
void DetectEngineIPOnlyThreadDeinit(DetectEngineIPOnlyThreadCtx *);
void IPOnlyAddSignature(DetectEngineCtx *, DetectEngineIPOnlyCtx *, Signature *);
void IPOnlyRegisterTests(void);

#endif /* __DETECT_ENGINE_IPONLY_H__ */


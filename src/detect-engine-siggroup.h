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

#ifndef __DETECT_ENGINE_SIGGROUP_H__
#define __DETECT_ENGINE_SIGGROUP_H__

void DetectSigGroupPrintMemory(void);

int SigGroupHeadAppendSig(DetectEngineCtx *, SigGroupHead **, Signature *);
int SigGroupHeadClearSigs(SigGroupHead *);
int SigGroupHeadCopySigs(DetectEngineCtx *, SigGroupHead *, SigGroupHead **);

int SigGroupHeadLoadContent(DetectEngineCtx *, SigGroupHead *);
int SigGroupHeadLoadUricontent(DetectEngineCtx *, SigGroupHead *);
int SigGroupHeadLoadStreamContent(DetectEngineCtx *, SigGroupHead *);
int SigGroupHeadClearContent(SigGroupHead *);
int SigGroupHeadClearUricontent(SigGroupHead *);
int SigGroupHeadClearStreamContent(SigGroupHead *);

void SigGroupHeadFree(SigGroupHead *);

void SigGroupHeadFreeMpmArrays(DetectEngineCtx *);

SigGroupHead *SigGroupHeadHashLookup(DetectEngineCtx *, SigGroupHead *);
SigGroupHead *SigGroupHeadMpmHashLookup(DetectEngineCtx *, SigGroupHead *);
SigGroupHead *SigGroupHeadMpmUriHashLookup(DetectEngineCtx *, SigGroupHead *);
SigGroupHead *SigGroupHeadMpmStreamHashLookup(DetectEngineCtx *, SigGroupHead *);
SigGroupHead *SigGroupHeadDPortHashLookup(DetectEngineCtx *, SigGroupHead *);
SigGroupHead *SigGroupHeadSPortHashLookup(DetectEngineCtx *, SigGroupHead *);

int SigGroupHeadMpmHashAdd(DetectEngineCtx *, SigGroupHead *);
int SigGroupHeadMpmUriHashAdd(DetectEngineCtx *, SigGroupHead *);
int SigGroupHeadMpmStreamHashAdd(DetectEngineCtx *, SigGroupHead *);
int SigGroupHeadHashAdd(DetectEngineCtx *, SigGroupHead *);
int SigGroupHeadDPortHashAdd(DetectEngineCtx *, SigGroupHead *);
int SigGroupHeadSPortHashAdd(DetectEngineCtx *, SigGroupHead *);

void SigGroupHeadHashFree(DetectEngineCtx *);
void SigGroupHeadMpmHashFree(DetectEngineCtx *);
void SigGroupHeadMpmUriHashFree(DetectEngineCtx *);
void SigGroupHeadMpmStreamHashFree(DetectEngineCtx *);
void SigGroupHeadDPortHashFree(DetectEngineCtx *);
void SigGroupHeadSPortHashFree(DetectEngineCtx *);

int SigGroupHeadHashInit(DetectEngineCtx *);
int SigGroupHeadMpmHashInit(DetectEngineCtx *);
int SigGroupHeadMpmUriHashInit(DetectEngineCtx *);
int SigGroupHeadDPortHashInit(DetectEngineCtx *);
int SigGroupHeadSPortHashInit(DetectEngineCtx *);

int SigGroupHeadHashRemove(DetectEngineCtx *, SigGroupHead *);
int SigGroupHeadSPortHashRemove(DetectEngineCtx *, SigGroupHead *);

void SigGroupHeadInitDataFree(SigGroupHeadInitData *sghid);
void SigGroupHeadSetSigCnt(SigGroupHead *sgh, uint32_t max_idx);
int SigGroupHeadBuildMatchArray (DetectEngineCtx *de_ctx, SigGroupHead *sgh,
                                 uint32_t max_idx);
void SigGroupHeadFreeSigArrays(DetectEngineCtx *de_ctx);

int SigGroupHeadContainsSigId (DetectEngineCtx *de_ctx, SigGroupHead *sgh,
                               uint32_t sid);

void SigGroupHeadRegisterTests(void);
void SigGroupHeadPrintSigs(DetectEngineCtx *de_ctx, SigGroupHead *sgh);

void SigGroupHeadStore(DetectEngineCtx *, SigGroupHead *);
void SigGroupHeadSetFilemagicFlag(DetectEngineCtx *, SigGroupHead *);
void SigGroupHeadSetFilestoreCount(DetectEngineCtx *, SigGroupHead *);
void SigGroupHeadSetFileMd5Flag(DetectEngineCtx *, SigGroupHead *);
void SigGroupHeadSetFilesizeFlag(DetectEngineCtx *, SigGroupHead *);
uint16_t SigGroupHeadGetMinMpmSize(DetectEngineCtx *de_ctx,
                                   SigGroupHead *sgh, int list);

int SigGroupHeadBuildNonMpmArray(DetectEngineCtx *de_ctx, SigGroupHead *sgh);

#endif /* __DETECT_ENGINE_SIGGROUP_H__ */

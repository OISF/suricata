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

#ifndef SURICATA_DETECT_ENGINE_SIGGROUP_H
#define SURICATA_DETECT_ENGINE_SIGGROUP_H

int SigGroupHeadAppendSig(const DetectEngineCtx *, SigGroupHead **, const Signature *);
int SigGroupHeadClearSigs(SigGroupHead *);
int SigGroupHeadCopySigs(DetectEngineCtx *, SigGroupHead *, SigGroupHead **);

void SigGroupHeadFree(const DetectEngineCtx *de_ctx, SigGroupHead *);

SigGroupHead *SigGroupHeadHashLookup(DetectEngineCtx *, SigGroupHead *);

int SigGroupHeadHashAdd(DetectEngineCtx *, SigGroupHead *);

void SigGroupHeadHashFree(DetectEngineCtx *);

int SigGroupHeadHashInit(DetectEngineCtx *);

void SigGroupHeadInitDataFree(SigGroupHeadInitData *sghid);
void SigGroupHeadSetSigCnt(SigGroupHead *sgh, uint32_t max_idx);
bool SigGroupHeadEqual(const SigGroupHead *, const SigGroupHead *);
void SigGroupHeadSetProtoAndDirection(SigGroupHead *sgh,
                                      uint8_t ipproto, int dir);
int SigGroupHeadBuildMatchArray(DetectEngineCtx *de_ctx, SigGroupHead *sgh, uint32_t max_idx);

int SigGroupHeadContainsSigId (DetectEngineCtx *de_ctx, SigGroupHead *sgh,
                               uint32_t sid);

void SigGroupHeadRegisterTests(void);
void SigGroupHeadPrintSigs(DetectEngineCtx *de_ctx, SigGroupHead *sgh);

void SigGroupHeadStore(DetectEngineCtx *, SigGroupHead *);

void SigGroupHeadSetupFiles(const DetectEngineCtx *de_ctx, SigGroupHead *sgh);

int SigGroupHeadBuildNonPrefilterArray(DetectEngineCtx *de_ctx, SigGroupHead *sgh);

#endif /* SURICATA_DETECT_ENGINE_SIGGROUP_H */

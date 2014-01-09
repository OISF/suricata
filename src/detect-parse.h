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

#ifndef __DETECT_PARSE_H__
#define __DETECT_PARSE_H__

/** Flags to indicate if the Signature parsing must be done
*   switching the source and dest (for ip addresses and ports)
*   or otherwise as normal */
enum {
    SIG_DIREC_NORMAL,
    SIG_DIREC_SWITCHED
};

/** Flags to indicate if are referencing the source of the Signature
*   or the destination (for ip addresses and ports)*/
enum {
    SIG_DIREC_SRC,
    SIG_DIREC_DST
};

/* prototypes */
int SigParse(DetectEngineCtx *,Signature *, char *, uint8_t);
Signature *SigAlloc(void);
void SigFree(Signature *s);
Signature *SigInit(DetectEngineCtx *,char *sigstr);
Signature *SigInitReal(DetectEngineCtx *, char *);
SigMatch *SigMatchGetLastSMFromLists(Signature *, int, ...);
void SigMatchTransferSigMatchAcrossLists(SigMatch *sm,
                                         SigMatch **, SigMatch **s,
                                         SigMatch **, SigMatch **);
void SigParsePrepare(void);
void SigParseRegisterTests(void);
Signature *DetectEngineAppendSig(DetectEngineCtx *, char *);

void SigMatchAppendSMToList(Signature *, SigMatch *, int);
void SigMatchRemoveSMFromList(Signature *, SigMatch *, int);
int SigMatchListSMBelongsTo(Signature *, SigMatch *);

int DetectParseDupSigHashInit(DetectEngineCtx *);
void DetectParseDupSigHashFree(DetectEngineCtx *);

int DetectEngineContentModifierBufferSetup(DetectEngineCtx *de_ctx, Signature *s, char *arg,
                                           uint8_t sm_type, uint8_t sm_list,
                                           AppProto alproto,  void (*CustomCallback)(Signature *s));

#endif /* __DETECT_PARSE_H__ */


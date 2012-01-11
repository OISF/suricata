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
SigMatch *SigMatchGetLastSM(SigMatch *, uint8_t);
SigMatch *SigMatchGetLastSMFromLists(Signature *, int, ...);
void SigMatchTransferSigMatchAcrossLists(SigMatch *sm,
                                         SigMatch **, SigMatch **s,
                                         SigMatch **, SigMatch **);
void SigParsePrepare(void);
void SigParseRegisterTests(void);
Signature *DetectEngineAppendSig(DetectEngineCtx *, char *);

void SigMatchReplace(Signature *, SigMatch *, SigMatch *);
void SigMatchReplaceContent(Signature *, SigMatch *, SigMatch *);
void SigMatchReplaceContentToUricontent(Signature *, SigMatch *, SigMatch *);

void SigMatchAppendPayload(Signature *, SigMatch *);
void SigMatchAppendDcePayload(Signature *, SigMatch *);
void SigMatchAppendPacket(Signature *, SigMatch *);
void SigMatchAppendPostMatch(Signature *, SigMatch *);
void SigMatchAppendUricontent(Signature *, SigMatch *);
void SigMatchAppendAppLayer(Signature *, SigMatch *);
void SigMatchAppendTag(Signature *, SigMatch *);
void SigMatchAppendSMToList(Signature *, SigMatch *, int);
void SigMatchRemoveSMFromList(Signature *, SigMatch *, int);
int SigMatchListSMBelongsTo(Signature *, SigMatch *);

int DetectParseDupSigHashInit(DetectEngineCtx *);
void DetectParseDupSigHashFree(DetectEngineCtx *);

int DetectParseContentString (char *, uint8_t **, uint16_t *, uint32_t *);

#endif /* __DETECT_PARSE_H__ */


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
Signature *SigAlloc(void);
void SigFree(Signature *s);
Signature *SigInit(DetectEngineCtx *, const char *sigstr);
Signature *SigInitReal(DetectEngineCtx *, const char *);
SigMatchData* SigMatchList2DataArray(SigMatch *head);
void SigParseRegisterTests(void);
Signature *DetectEngineAppendSig(DetectEngineCtx *, const char *);

void SigMatchAppendSMToList(Signature *, SigMatch *, int);
void SigMatchRemoveSMFromList(Signature *, SigMatch *, int);
int SigMatchListSMBelongsTo(const Signature *, const SigMatch *);

int DetectParseDupSigHashInit(DetectEngineCtx *);
void DetectParseDupSigHashFree(DetectEngineCtx *);

int DetectEngineContentModifierBufferSetup(DetectEngineCtx *de_ctx,
        Signature *s, const char *arg, int sm_type, int sm_list,
        AppProto alproto);

const char *DetectListToHumanString(int list);
const char *DetectListToString(int list);

SigMatch *DetectGetLastSM(const Signature *);
SigMatch *DetectGetLastSMFromMpmLists(const DetectEngineCtx *de_ctx, const Signature *s);
SigMatch *DetectGetLastSMFromLists(const Signature *s, ...);
SigMatch *DetectGetLastSMByListPtr(const Signature *s, SigMatch *sm_list, ...);
SigMatch *DetectGetLastSMByListId(const Signature *s, int list_id, ...);

int DetectSignatureAddTransform(Signature *s, int transform);
int DetectSignatureSetAppProto(Signature *s, AppProto alproto);

/* parse regex setup and free util funcs */

void DetectSetupParseRegexes(const char *parse_str,
                             pcre **parse_regex,
                             pcre_extra **parse_regex_study);
void DetectParseRegexAddToFreeList(pcre *regex, pcre_extra *study);
void DetectParseFreeRegexes(void);

#ifdef AFLFUZZ_RULES
int RuleParseDataFromFile(char *filename);
#endif

#endif /* __DETECT_PARSE_H__ */


/* Copyright (C) 2007-2020 Open Information Security Foundation
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

#ifndef SURICATA_DETECT_PARSE_H
#define SURICATA_DETECT_PARSE_H

#include "app-layer-protos.h"
#include "detect-engine-register.h"
// types from detect.h with only forward declarations for bindgen
typedef struct DetectEngineCtx_ DetectEngineCtx;
typedef struct Signature_ Signature;
typedef struct SigMatchCtx_ SigMatchCtx;
typedef struct SigMatch_ SigMatch;
typedef struct SigMatchData_ SigMatchData;

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
int SignatureInitDataBufferCheckExpand(Signature *s);
Signature *SigAlloc(void);
void SigFree(DetectEngineCtx *de_ctx, Signature *s);
Signature *SigInit(DetectEngineCtx *, const char *sigstr);
SigMatchData* SigMatchList2DataArray(SigMatch *head);
void SigParseRegisterTests(void);
Signature *DetectEngineAppendSig(DetectEngineCtx *, const char *);
Signature *DetectFirewallRuleAppendNew(DetectEngineCtx *, const char *);

SigMatch *SCSigMatchAppendSMToList(DetectEngineCtx *, Signature *, uint16_t, SigMatchCtx *, int);
void SigMatchRemoveSMFromList(Signature *, SigMatch *, int);
int SigMatchListSMBelongsTo(const Signature *, const SigMatch *);

int DetectParseDupSigHashInit(DetectEngineCtx *);
void DetectParseDupSigHashFree(DetectEngineCtx *);

int DetectEngineContentModifierBufferSetup(DetectEngineCtx *de_ctx,
        Signature *s, const char *arg, int sm_type, int sm_list,
        AppProto alproto);

bool SigMatchSilentErrorEnabled(const DetectEngineCtx *de_ctx,
        const enum DetectKeywordId id);
bool SigMatchStrictEnabled(const enum DetectKeywordId id);

const char *DetectListToHumanString(int list);
const char *DetectListToString(int list);

void SigTableApplyStrictCommandLineOption(const char *str);

SigMatch *DetectGetLastSM(const Signature *);
SigMatch *DetectGetLastSMFromMpmLists(const DetectEngineCtx *de_ctx, const Signature *s);
SigMatch *DetectGetLastSMFromLists(const Signature *s, ...);
SigMatch *DetectGetLastSMByListPtr(const Signature *s, SigMatch *sm_list, ...);
SigMatch *DetectGetLastSMByListId(const Signature *s, int list_id, ...);

int WARN_UNUSED SCDetectSignatureSetAppProto(Signature *s, AppProto alproto);
int WARN_UNUSED DetectSignatureSetMultiAppProto(Signature *s, const AppProto *alprotos);

/* parse regex setup and free util funcs */

#ifndef SURICATA_BINDGEN_H
typedef struct DetectParseRegex {
    pcre2_code *regex;
    pcre2_match_context *context;
    struct DetectParseRegex *next;
} DetectParseRegex;

DetectParseRegex *DetectSetupPCRE2(const char *parse_str, int opts);
bool DetectSetupParseRegexesOpts(const char *parse_str, DetectParseRegex *parse_regex, int opts);
void DetectSetupParseRegexes(const char *parse_str, DetectParseRegex *parse_regex);
void DetectParseRegexAddToFreeList(DetectParseRegex *parse_regex);
void DetectParseFreeRegexes(void);
void DetectParseFreeRegex(DetectParseRegex *r);

/* parse regex exec */
int DetectParsePcreExec(DetectParseRegex *parse_regex, pcre2_match_data **match, const char *str,
        int start_offset, int options);
int SC_Pcre2SubstringCopy(
        pcre2_match_data *match_data, uint32_t number, PCRE2_UCHAR *buffer, PCRE2_SIZE *bufflen);
int SC_Pcre2SubstringGet(pcre2_match_data *match_data, uint32_t number, PCRE2_UCHAR **bufferptr,
        PCRE2_SIZE *bufflen);
#endif

void DetectRegisterAppLayerHookLists(void);

#endif /* SURICATA_DETECT_PARSE_H */

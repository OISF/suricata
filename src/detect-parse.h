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

#include "detect.h"
#include "detect-engine-mpm.h"

/* File handler registration */
#define MAX_DETECT_ALPROTO_CNT 10
typedef struct DetectFileHandlerTableElmt_ {
    const char *name;
    int priority;
    PrefilterRegisterFunc PrefilterFn;
    InspectEngineFuncPtr Callback;
    InspectionBufferGetDataPtr GetData;
    int al_protocols[MAX_DETECT_ALPROTO_CNT];
    int tx_progress;
    int progress;
} DetectFileHandlerTableElmt;
void DetectFileRegisterFileProtocols(DetectFileHandlerTableElmt *entry);

/* File registration table */
extern DetectFileHandlerTableElmt filehandler_table[DETECT_TBLSIZE_STATIC];

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

typedef struct DetectParseRegex {
    pcre2_code *regex;
    pcre2_match_context *context;
    struct DetectParseRegex *next;
} DetectParseRegex;

/* prototypes */
int SignatureInitDataBufferCheckExpand(Signature *s);
Signature *SigAlloc(void);
void SigFree(DetectEngineCtx *de_ctx, Signature *s);
Signature *SigInit(DetectEngineCtx *, const char *sigstr);
SigMatchData* SigMatchList2DataArray(SigMatch *head);
void SigParseRegisterTests(void);
Signature *DetectEngineAppendSig(DetectEngineCtx *, const char *);

SigMatch *SigMatchAppendSMToList(DetectEngineCtx *, Signature *, uint16_t, SigMatchCtx *, int);
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

int DetectSignatureAddTransform(Signature *s, int transform, void *options);
int WARN_UNUSED DetectSignatureSetAppProto(Signature *s, AppProto alproto);
int WARN_UNUSED DetectSignatureSetMultiAppProto(Signature *s, const AppProto *alprotos);

/* parse regex setup and free util funcs */

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

int DetectSetupDirection(Signature *s, const char *str);
void DetectRegisterAppLayerHookLists(void);

#endif /* SURICATA_DETECT_PARSE_H */

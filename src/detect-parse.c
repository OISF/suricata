/* Copyright (C) 2007-2021 Open Information Security Foundation
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
 *
 * signature parser
 */

#include "suricata-common.h"
#include "debug.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-engine-address.h"
#include "detect-engine-port.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"

#include "detect-content.h"
#include "detect-pcre.h"
#include "detect-uricontent.h"
#include "detect-reference.h"
#include "detect-ipproto.h"
#include "detect-flow.h"
#include "detect-app-layer-protocol.h"
#include "detect-lua.h"
#include "detect-app-layer-event.h"
#include "detect-http-method.h"

#include "pkt-var.h"
#include "host.h"
#include "util-profiling.h"
#include "decode.h"

#include "flow.h"

#include "util-rule-vars.h"
#include "conf.h"
#include "conf-yaml-loader.h"

#include "app-layer.h"
#include "app-layer-protos.h"
#include "app-layer-parser.h"
#include "app-layer-htp.h"

#include "util-classification-config.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-debug.h"
#include "string.h"
#include "detect-parse.h"
#include "detect-engine-iponly.h"
#include "app-layer-detect-proto.h"

/* Table with all SigMatch registrations */
SigTableElmt sigmatch_table[DETECT_TBLSIZE];

extern int sc_set_caps;

static void SigMatchTransferSigMatchAcrossLists(SigMatch *sm,
        SigMatch **src_sm_list, SigMatch **src_sm_list_tail,
        SigMatch **dst_sm_list, SigMatch **dst_sm_list_tail);

/**
 * \brief We use this as data to the hash table DetectEngineCtx->dup_sig_hash_table.
 */
typedef struct SigDuplWrapper_ {
    /* the signature we want to wrap */
    Signature *s;
    /* the signature right before the above signature in the det_ctx->sig_list */
    Signature *s_prev;
} SigDuplWrapper;

#define CONFIG_PARTS 8

#define CONFIG_ACTION 0
#define CONFIG_PROTO  1
#define CONFIG_SRC    2
#define CONFIG_SP     3
#define CONFIG_DIREC  4
#define CONFIG_DST    5
#define CONFIG_DP     6
#define CONFIG_OPTS   7

/** helper structure for sig parsing */
typedef struct SignatureParser_ {
    char action[DETECT_MAX_RULE_SIZE];
    char protocol[DETECT_MAX_RULE_SIZE];
    char direction[DETECT_MAX_RULE_SIZE];
    char src[DETECT_MAX_RULE_SIZE];
    char dst[DETECT_MAX_RULE_SIZE];
    char sp[DETECT_MAX_RULE_SIZE];
    char dp[DETECT_MAX_RULE_SIZE];
    char opts[DETECT_MAX_RULE_SIZE];
} SignatureParser;

const char *DetectListToHumanString(int list)
{
#define CASE_CODE_STRING(E, S)  case E: return S; break
    switch (list) {
        CASE_CODE_STRING(DETECT_SM_LIST_MATCH, "packet");
        CASE_CODE_STRING(DETECT_SM_LIST_PMATCH, "payload");
        CASE_CODE_STRING(DETECT_SM_LIST_TMATCH, "tag");
        CASE_CODE_STRING(DETECT_SM_LIST_POSTMATCH, "postmatch");
        CASE_CODE_STRING(DETECT_SM_LIST_SUPPRESS, "suppress");
        CASE_CODE_STRING(DETECT_SM_LIST_THRESHOLD, "threshold");
        CASE_CODE_STRING(DETECT_SM_LIST_MAX, "max (internal)");
    }
#undef CASE_CODE_STRING
    return "unknown";
}

#define CASE_CODE(E)  case E: return #E
const char *DetectListToString(int list)
{
    switch (list) {
        CASE_CODE(DETECT_SM_LIST_MATCH);
        CASE_CODE(DETECT_SM_LIST_PMATCH);
        CASE_CODE(DETECT_SM_LIST_TMATCH);
        CASE_CODE(DETECT_SM_LIST_POSTMATCH);
        CASE_CODE(DETECT_SM_LIST_SUPPRESS);
        CASE_CODE(DETECT_SM_LIST_THRESHOLD);
        CASE_CODE(DETECT_SM_LIST_MAX);
    }
    return "unknown";
}

/** \param arg NULL or empty string */
int DetectEngineContentModifierBufferSetup(DetectEngineCtx *de_ctx,
        Signature *s, const char *arg, int sm_type, int sm_list,
        AppProto alproto)
{
    SigMatch *sm = NULL;
    int ret = -1;

    if (arg != NULL && strcmp(arg, "") != 0) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "%s shouldn't be supplied "
                   "with an argument", sigmatch_table[sm_type].name);
        goto end;
    }

    if (s->init_data->list != DETECT_SM_LIST_NOTSET) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "\"%s\" keyword seen "
                   "with a sticky buffer still set.  Reset sticky buffer "
                   "with pkt_data before using the modifier.",
                   sigmatch_table[sm_type].name);
        goto end;
    }
    if (s->alproto != ALPROTO_UNKNOWN && !AppProtoEquals(s->alproto, alproto)) {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "rule contains conflicting "
                   "alprotos set");
        goto end;
    }

    sm = DetectGetLastSMByListId(s,
            DETECT_SM_LIST_PMATCH, DETECT_CONTENT, -1);
    if (sm == NULL) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "\"%s\" keyword "
                   "found inside the rule without a content context.  "
                   "Please use a \"content\" keyword before using the "
                   "\"%s\" keyword", sigmatch_table[sm_type].name,
                   sigmatch_table[sm_type].name);
        goto end;
    }
    DetectContentData *cd = (DetectContentData *)sm->ctx;
    if (cd->flags & DETECT_CONTENT_RAWBYTES) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "%s rule can not "
                   "be used with the rawbytes rule keyword",
                   sigmatch_table[sm_type].name);
        goto end;
    }
    if (cd->flags & DETECT_CONTENT_REPLACE) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "%s rule can not "
                   "be used with the replace rule keyword",
                   sigmatch_table[sm_type].name);
        goto end;
    }
    if (cd->flags & (DETECT_CONTENT_WITHIN | DETECT_CONTENT_DISTANCE)) {
        SigMatch *pm = DetectGetLastSMByListPtr(s, sm->prev,
            DETECT_CONTENT, DETECT_PCRE, -1);
        if (pm != NULL) {
            if (pm->type == DETECT_CONTENT) {
                DetectContentData *tmp_cd = (DetectContentData *)pm->ctx;
                tmp_cd->flags &= ~DETECT_CONTENT_RELATIVE_NEXT;
            } else {
                DetectPcreData *tmp_pd = (DetectPcreData *)pm->ctx;
                tmp_pd->flags &= ~DETECT_PCRE_RELATIVE_NEXT;
            }
        }

        pm = DetectGetLastSMByListId(s, sm_list,
            DETECT_CONTENT, DETECT_PCRE, -1);
        if (pm != NULL) {
            if (pm->type == DETECT_CONTENT) {
                DetectContentData *tmp_cd = (DetectContentData *)pm->ctx;
                tmp_cd->flags |= DETECT_CONTENT_RELATIVE_NEXT;
            } else {
                DetectPcreData *tmp_pd = (DetectPcreData *)pm->ctx;
                tmp_pd->flags |= DETECT_PCRE_RELATIVE_NEXT;
            }
        }
    }
    s->alproto = alproto;
    s->flags |= SIG_FLAG_APPLAYER;

    /* transfer the sm from the pmatch list to sm_list */
    SigMatchTransferSigMatchAcrossLists(sm,
                                        &s->init_data->smlists[DETECT_SM_LIST_PMATCH],
                                        &s->init_data->smlists_tail[DETECT_SM_LIST_PMATCH],
                                        &s->init_data->smlists[sm_list],
                                        &s->init_data->smlists_tail[sm_list]);

    ret = 0;
 end:
    return ret;
}

SigMatch *SigMatchAlloc(void)
{
    SigMatch *sm = SCMalloc(sizeof(SigMatch));
    if (unlikely(sm == NULL))
        return NULL;

    memset(sm, 0, sizeof(SigMatch));
    sm->prev = NULL;
    sm->next = NULL;
    return sm;
}

/** \brief free a SigMatch
 *  \param sm SigMatch to free.
 */
void SigMatchFree(DetectEngineCtx *de_ctx, SigMatch *sm)
{
    if (sm == NULL)
        return;

    /** free the ctx, for that we call the Free func */
    if (sm->ctx != NULL) {
        if (sigmatch_table[sm->type].Free != NULL) {
            sigmatch_table[sm->type].Free(de_ctx, sm->ctx);
        }
    }
    SCFree(sm);
}

static enum DetectKeywordId SigTableGetIndex(const SigTableElmt *e)
{
    const SigTableElmt *table = &sigmatch_table[0];
    ptrdiff_t offset = e - table;
    BUG_ON(offset >= DETECT_TBLSIZE);
    return (enum DetectKeywordId)offset;
}

/* Get the detection module by name */
static SigTableElmt *SigTableGet(char *name)
{
    SigTableElmt *st = NULL;
    int i = 0;

    for (i = 0; i < DETECT_TBLSIZE; i++) {
        st = &sigmatch_table[i];

        if (st->name != NULL) {
            if (strcasecmp(name,st->name) == 0)
                return st;
            if (st->alias != NULL && strcasecmp(name,st->alias) == 0)
                return st;
        }
    }

    return NULL;
}

bool SigMatchSilentErrorEnabled(const DetectEngineCtx *de_ctx,
        const enum DetectKeywordId id)
{
    return de_ctx->sm_types_silent_error[id];
}

bool SigMatchStrictEnabled(const enum DetectKeywordId id)
{
    if (id < DETECT_TBLSIZE) {
        return ((sigmatch_table[id].flags & SIGMATCH_STRICT_PARSING) != 0);
    }
    return false;
}

void SigTableApplyStrictCommandlineOption(const char *str)
{
    if (str == NULL) {
        /* nothing to be done */
        return;
    }

    /* "all" just sets the flag for each keyword */
    if (strcmp(str, "all") == 0) {
        for (int i = 0; i < DETECT_TBLSIZE; i++) {
            SigTableElmt *st = &sigmatch_table[i];
            st->flags |= SIGMATCH_STRICT_PARSING;
        }
        return;
    }

    char *copy = SCStrdup(str);
    if (copy == NULL)
        FatalError(SC_ERR_MEM_ALLOC, "could not duplicate opt string");

    char *xsaveptr = NULL;
    char *key = strtok_r(copy, ",", &xsaveptr);
    while (key != NULL) {
        SigTableElmt *st = SigTableGet(key);
        if (st != NULL) {
            st->flags |= SIGMATCH_STRICT_PARSING;
        } else {
            SCLogWarning(SC_ERR_CMD_LINE, "'strict' command line "
                    "argument '%s' not found", key);
        }
        key = strtok_r(NULL, ",", &xsaveptr);
    }

    SCFree(copy);
}

/**
 * \brief Append a SigMatch to the list type.
 *
 * \param s    Signature.
 * \param new  The sig match to append.
 * \param list The list to append to.
 */
void SigMatchAppendSMToList(Signature *s, SigMatch *new, int list)
{
    if (list > 0 && (uint32_t)list >= s->init_data->smlists_array_size)
    {
        uint32_t old_size = s->init_data->smlists_array_size;
        uint32_t new_size = (uint32_t)list + 1;
        void *ptr = SCRealloc(s->init_data->smlists, (new_size * sizeof(SigMatch *)));
        if (ptr == NULL)
            abort();
        s->init_data->smlists = ptr;
        ptr = SCRealloc(s->init_data->smlists_tail, (new_size * sizeof(SigMatch *)));
        if (ptr == NULL)
            abort();
        s->init_data->smlists_tail = ptr;
        for (uint32_t i = old_size; i < new_size; i++) {
            s->init_data->smlists[i] = NULL;
            s->init_data->smlists_tail[i] = NULL;
        }
        s->init_data->smlists_array_size = new_size;
    }

    if (s->init_data->smlists[list] == NULL) {
        s->init_data->smlists[list] = new;
        s->init_data->smlists_tail[list] = new;
        new->next = NULL;
        new->prev = NULL;
    } else {
        SigMatch *cur = s->init_data->smlists_tail[list];
        cur->next = new;
        new->prev = cur;
        new->next = NULL;
        s->init_data->smlists_tail[list] = new;
    }

    new->idx = s->init_data->sm_cnt;
    s->init_data->sm_cnt++;
}

void SigMatchRemoveSMFromList(Signature *s, SigMatch *sm, int sm_list)
{
    if (sm == s->init_data->smlists[sm_list]) {
        s->init_data->smlists[sm_list] = sm->next;
    }
    if (sm == s->init_data->smlists_tail[sm_list]) {
        s->init_data->smlists_tail[sm_list] = sm->prev;
    }
    if (sm->prev != NULL)
        sm->prev->next = sm->next;
    if (sm->next != NULL)
        sm->next->prev = sm->prev;

    return;
}

/**
 * \brief Returns a pointer to the last SigMatch instance of a particular type
 *        in a Signature of the payload list.
 *
 * \param s    Pointer to the tail of the sigmatch list
 * \param type SigMatch type which has to be searched for in the Signature.
 *
 * \retval match Pointer to the last SigMatch instance of type 'type'.
 */
static SigMatch *SigMatchGetLastSMByType(SigMatch *sm, int type)
{
    while (sm != NULL) {
        if (sm->type == type) {
            return sm;
        }
        sm = sm->prev;
    }

    return NULL;
}

/** \brief get the last SigMatch from lists that support
 *         MPM.
 *  \note only supports the lists that are registered through
 *        DetectBufferTypeSupportsMpm().
 */
SigMatch *DetectGetLastSMFromMpmLists(const DetectEngineCtx *de_ctx, const Signature *s)
{
    SigMatch *sm_last = NULL;
    SigMatch *sm_new;
    uint32_t sm_type;

    /* if we have a sticky buffer, use that */
    if (s->init_data->list != DETECT_SM_LIST_NOTSET) {
        if (!(DetectEngineBufferTypeSupportsMpmGetById(de_ctx, s->init_data->list))) {
            return NULL;
        }

        sm_last = DetectGetLastSMByListPtr(s,
                s->init_data->smlists_tail[s->init_data->list],
                DETECT_CONTENT, -1);
        return sm_last;
    }

    /* otherwise brute force it */
    for (sm_type = 0; sm_type < s->init_data->smlists_array_size; sm_type++) {
        if (!DetectEngineBufferTypeSupportsMpmGetById(de_ctx, sm_type))
            continue;
        SigMatch *sm_list = s->init_data->smlists_tail[sm_type];
        sm_new = SigMatchGetLastSMByType(sm_list, DETECT_CONTENT);
        if (sm_new == NULL)
            continue;
        if (sm_last == NULL || sm_new->idx > sm_last->idx)
            sm_last = sm_new;
    }

    return sm_last;
}

/**
 * \brief Returns the sm with the largest index (added latest) from the lists
 *        passed to us.
 *
 * \retval Pointer to Last sm.
 */
SigMatch *DetectGetLastSMFromLists(const Signature *s, ...)
{
    SigMatch *sm_last = NULL;
    SigMatch *sm_new;

    /* otherwise brute force it */
    for (int buf_type = 0; buf_type < (int)s->init_data->smlists_array_size; buf_type++) {
        if (s->init_data->smlists[buf_type] == NULL)
            continue;
        if (s->init_data->list != DETECT_SM_LIST_NOTSET &&
            buf_type != s->init_data->list)
            continue;

        int sm_type;
        va_list ap;
        va_start(ap, s);

        for (sm_type = va_arg(ap, int); sm_type != -1; sm_type = va_arg(ap, int))
        {
            sm_new = SigMatchGetLastSMByType(s->init_data->smlists_tail[buf_type], sm_type);
            if (sm_new == NULL)
                continue;
            if (sm_last == NULL || sm_new->idx > sm_last->idx)
                sm_last = sm_new;
        }
        va_end(ap);
    }

    return sm_last;
}

/**
 * \brief Returns the sm with the largest index (added last) from the list
 *        passed to us as a pointer.
 *
 * \param sm_list pointer to the SigMatch we should look before
 * \param va_args list of keyword types terminated by -1
 *
 * \retval sm_last to last sm.
 */
SigMatch *DetectGetLastSMByListPtr(const Signature *s, SigMatch *sm_list, ...)
{
    SigMatch *sm_last = NULL;
    SigMatch *sm_new;
    int sm_type;

    va_list ap;
    va_start(ap, sm_list);

    for (sm_type = va_arg(ap, int); sm_type != -1; sm_type = va_arg(ap, int))
    {
        sm_new = SigMatchGetLastSMByType(sm_list, sm_type);
        if (sm_new == NULL)
            continue;
        if (sm_last == NULL || sm_new->idx > sm_last->idx)
            sm_last = sm_new;
    }

    va_end(ap);

    return sm_last;
}

/**
 * \brief Returns the sm with the largest index (added last) from the list
 *        passed to us as an id.
 *
 * \param list_id id of the list to be searched
 * \param va_args list of keyword types terminated by -1
 *
 * \retval sm_last to last sm.
 */
SigMatch *DetectGetLastSMByListId(const Signature *s, int list_id, ...)
{
    SigMatch *sm_last = NULL;
    SigMatch *sm_new;
    int sm_type;

    if ((uint32_t)list_id >= s->init_data->smlists_array_size) {
        return NULL;
    }
    SigMatch *sm_list = s->init_data->smlists_tail[list_id];
    if (sm_list == NULL)
        return NULL;

    va_list ap;
    va_start(ap, list_id);

    for (sm_type = va_arg(ap, int); sm_type != -1; sm_type = va_arg(ap, int))
    {
        sm_new = SigMatchGetLastSMByType(sm_list, sm_type);
        if (sm_new == NULL)
            continue;
        if (sm_last == NULL || sm_new->idx > sm_last->idx)
            sm_last = sm_new;
    }

    va_end(ap);

    return sm_last;
}

/**
 * \brief Returns the sm with the largest index (added latest) from this sig
 *
 * \retval sm_last Pointer to last sm
 */
SigMatch *DetectGetLastSM(const Signature *s)
{
    const int nlists = s->init_data->smlists_array_size;
    SigMatch *sm_last = NULL;
    SigMatch *sm_new;
    int i;

    for (i = 0; i < nlists; i ++) {
        sm_new = s->init_data->smlists_tail[i];
        if (sm_new == NULL)
            continue;
        if (sm_last == NULL || sm_new->idx > sm_last->idx)
            sm_last = sm_new;
    }

    return sm_last;
}

static void SigMatchTransferSigMatchAcrossLists(SigMatch *sm,
        SigMatch **src_sm_list, SigMatch **src_sm_list_tail,
        SigMatch **dst_sm_list, SigMatch **dst_sm_list_tail)
{
    /* we won't do any checks for args */

    if (sm->prev != NULL)
        sm->prev->next = sm->next;
    if (sm->next != NULL)
        sm->next->prev = sm->prev;

    if (sm == *src_sm_list)
        *src_sm_list = sm->next;
    if (sm == *src_sm_list_tail)
        *src_sm_list_tail = sm->prev;

    if (*dst_sm_list == NULL) {
        *dst_sm_list = sm;
        *dst_sm_list_tail = sm;
        sm->next = NULL;
        sm->prev = NULL;
    } else {
        SigMatch *cur = *dst_sm_list_tail;
        cur->next = sm;
        sm->prev = cur;
        sm->next = NULL;
        *dst_sm_list_tail = sm;
    }

    return;
}

int SigMatchListSMBelongsTo(const Signature *s, const SigMatch *key_sm)
{
    if (key_sm == NULL)
        return -1;

    const int nlists = s->init_data->smlists_array_size;
    for (int list = 0; list < nlists; list++) {
        const SigMatch *sm = s->init_data->smlists[list];
        while (sm != NULL) {
            if (sm == key_sm)
                return list;
            sm = sm->next;
        }
    }

    SCLogError(SC_ERR_INVALID_SIGNATURE, "Unable to find the sm in any of the "
               "sm lists");
    return -1;
}

static int SigParseOptions(DetectEngineCtx *de_ctx, Signature *s, char *optstr, char *output, size_t output_size)
{
    SigTableElmt *st = NULL;
    char *optname = NULL;
    char *optvalue = NULL;

    /* Trim leading space. */
    while (isblank(*optstr)) {
        optstr++;
    }

    /* Look for the end of this option, handling escaped semicolons. */
    char *optend = optstr;
    for (;;) {
        optend = strchr(optend, ';');
        if (optend == NULL) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "no terminating \";\" found");
            goto error;
        }
        else if (optend > optstr && *(optend -1 ) == '\\') {
            optend++;
        } else {
            break;
        }
    }
    *(optend++) = '\0';

    /* Find the start of the option value. */
    char *optvalptr = strchr(optstr, ':');
    if (optvalptr) {
        *(optvalptr++) = '\0';

        /* Trim trailing space from name. */
        for (size_t i = strlen(optvalptr); i > 0; i--) {
            if (isblank(optvalptr[i - 1])) {
                optvalptr[i - 1] = '\0';
            } else {
                break;
            }
        }

        optvalue = optvalptr;
    }

    /* Trim trailing space from name. */
    for (size_t i = strlen(optstr); i > 0; i--) {
        if (isblank(optstr[i - 1])) {
            optstr[i - 1] = '\0';
        } else {
            break;
        }
    }
    optname = optstr;

    /* Call option parsing */
    st = SigTableGet(optname);
    if (st == NULL || st->Setup == NULL) {
        SCLogError(SC_ERR_RULE_KEYWORD_UNKNOWN, "unknown rule keyword '%s'.", optname);
        goto error;
    }

    if (!(st->flags & (SIGMATCH_NOOPT|SIGMATCH_OPTIONAL_OPT))) {
        if (optvalue == NULL || strlen(optvalue) == 0) {
            SCLogError(SC_ERR_INVALID_SIGNATURE,
                    "invalid formatting or malformed option to %s keyword: '%s'", optname, optstr);
            goto error;
        }
    } else if (st->flags & SIGMATCH_NOOPT) {
        if (optvalue && strlen(optvalue)) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "unexpected option to %s keyword: '%s'", optname,
                    optstr);
            goto error;
        }
    }
    s->init_data->negated = false;

    if (st->flags & SIGMATCH_INFO_DEPRECATED) {
#define URL "https://suricata-ids.org/about/deprecation-policy/"
        if (st->alternative == 0)
            SCLogWarning(SC_WARN_DEPRECATED, "keyword '%s' is deprecated "
                    "and will be removed soon. See %s", st->name, URL);
        else
            SCLogWarning(SC_WARN_DEPRECATED, "keyword '%s' is deprecated "
                    "and will be removed soon. Use '%s' instead. "
                    "See %s", st->name, sigmatch_table[st->alternative].name, URL);
#undef URL
    }

    int setup_ret = 0;

    /* Validate double quoting, trimming trailing white space along the way. */
    if (optvalue != NULL && strlen(optvalue) > 0) {
        size_t ovlen = strlen(optvalue);
        char *ptr = optvalue;

        /* skip leading whitespace */
        while (ovlen > 0) {
            if (!isblank(*ptr))
                break;
            ptr++;
            ovlen--;
        }
        if (ovlen == 0) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "invalid formatting or malformed option to %s keyword: \'%s\'",
                    optname, optstr);
            goto error;
        }

        /* see if value is negated */
        if ((st->flags & SIGMATCH_HANDLE_NEGATION) && *ptr == '!') {
            s->init_data->negated = true;
            ptr++;
            ovlen--;
        }
        /* skip more whitespace */
        while (ovlen > 0) {
            if (!isblank(*ptr))
                break;
            ptr++;
            ovlen--;
        }
        if (ovlen == 0) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "invalid formatting or malformed option to %s keyword: \'%s\'",
                    optname, optstr);
            goto error;
        }
        /* if quoting is mandatory, enforce it */
        if (st->flags & SIGMATCH_QUOTES_MANDATORY && ovlen && *ptr != '"') {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "invalid formatting to %s keyword: "
                    "value must be double quoted \'%s\'", optname, optstr);
            goto error;
        }

        if ((st->flags & (SIGMATCH_QUOTES_OPTIONAL|SIGMATCH_QUOTES_MANDATORY))
                && ovlen && *ptr == '"')
        {
            for (; ovlen > 0; ovlen--) {
                if (isblank(ptr[ovlen - 1])) {
                    ptr[ovlen - 1] = '\0';
                } else {
                    break;
                }
            }
            if (ovlen && ptr[ovlen - 1] != '"') {
                SCLogError(SC_ERR_INVALID_SIGNATURE,
                    "bad option value formatting (possible missing semicolon) "
                    "for keyword %s: \'%s\'", optname, optvalue);
                goto error;
            }
            if (ovlen > 1) {
                /* strip leading " */
                ptr++;
                ovlen--;
                ptr[ovlen - 1] = '\0';
                ovlen--;
            }
            if (ovlen == 0) {
                SCLogError(SC_ERR_INVALID_SIGNATURE,
                    "bad input "
                    "for keyword %s: \'%s\'", optname, optvalue);
                goto error;
            }
        } else {
            if (*ptr == '"') {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "quotes on %s keyword that doesn't support them: \'%s\'",
                        optname, optstr);
                goto error;
            }
        }
        /* setup may or may not add a new SigMatch to the list */
        setup_ret = st->Setup(de_ctx, s, ptr);
    } else {
        /* setup may or may not add a new SigMatch to the list */
        setup_ret = st->Setup(de_ctx, s, NULL);
    }
    if (setup_ret < 0) {
        SCLogDebug("\"%s\" failed to setup", st->name);

        /* handle 'silent' error case */
        if (setup_ret == -2) {
            enum DetectKeywordId idx = SigTableGetIndex(st);
            if (de_ctx->sm_types_silent_error[idx] == false) {
                de_ctx->sm_types_silent_error[idx] = true;
                return -1;
            }
            return -2;
        }
        return setup_ret;
    }
    s->init_data->negated = false;

    if (strlen(optend) > 0) {
        strlcpy(output, optend, output_size);
        return 1;
    }

    return 0;

error:
    return -1;
}

/** \brief Parse address string and update signature
 *
 *  \retval 0 ok, -1 error
 */
static int SigParseAddress(DetectEngineCtx *de_ctx,
        Signature *s, const char *addrstr, char flag)
{
    SCLogDebug("Address Group \"%s\" to be parsed now", addrstr);

    /* pass on to the address(list) parser */
    if (flag == 0) {
        if (strcasecmp(addrstr, "any") == 0)
            s->flags |= SIG_FLAG_SRC_ANY;

        s->init_data->src = DetectParseAddress(de_ctx, addrstr,
                &s->init_data->src_contains_negation);
        if (s->init_data->src == NULL)
            goto error;
    } else {
        if (strcasecmp(addrstr, "any") == 0)
            s->flags |= SIG_FLAG_DST_ANY;

        s->init_data->dst = DetectParseAddress(de_ctx, addrstr,
                &s->init_data->dst_contains_negation);
        if (s->init_data->dst == NULL)
            goto error;
    }

    return 0;

error:
    return -1;
}

/**
 * \brief Parses the protocol supplied by the Signature.
 *
 *        http://www.iana.org/assignments/protocol-numbers
 *
 * \param s        Pointer to the Signature instance to which the parsed
 *                 protocol has to be added.
 * \param protostr Pointer to the character string containing the protocol name.
 *
 * \retval  0 On successfully parsing the protocl sent as the argument.
 * \retval -1 On failure
 */
static int SigParseProto(Signature *s, const char *protostr)
{
    SCEnter();

    int r = DetectProtoParse(&s->proto, (char *)protostr);
    if (r < 0) {
        s->alproto = AppLayerGetProtoByName((char *)protostr);
        /* indicate that the signature is app-layer */
        if (s->alproto != ALPROTO_UNKNOWN) {
            s->flags |= SIG_FLAG_APPLAYER;

            AppLayerProtoDetectSupportedIpprotos(s->alproto, s->proto.proto);
        }
        else {
            SCLogError(SC_ERR_UNKNOWN_PROTOCOL, "protocol \"%s\" cannot be used "
                       "in a signature.  Either detection for this protocol "
                       "is not yet supported OR detection has been disabled for "
                       "protocol through the yaml option "
                       "app-layer.protocols.%s.detection-enabled", protostr,
                       protostr);
            SCReturnInt(-1);
        }
    }

    /* if any of these flags are set they are set in a mutually exclusive
     * manner */
    if (s->proto.flags & DETECT_PROTO_ONLY_PKT) {
        s->flags |= SIG_FLAG_REQUIRE_PACKET;
    } else if (s->proto.flags & DETECT_PROTO_ONLY_STREAM) {
        s->flags |= SIG_FLAG_REQUIRE_STREAM;
    }

    SCReturnInt(0);
}

/**
 * \brief Parses the port(source or destination) field, from a Signature.
 *
 * \param s       Pointer to the signature which has to be updated with the
 *                port information.
 * \param portstr Pointer to the character string containing the port info.
 * \param         Flag which indicates if the portstr received is src or dst
 *                port.  For src port: flag = 0, dst port: flag = 1.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
static int SigParsePort(const DetectEngineCtx *de_ctx,
        Signature *s, const char *portstr, char flag)
{
    int r = 0;

    /* XXX VJ exclude handling this for none UDP/TCP proto's */

    SCLogDebug("Port group \"%s\" to be parsed", portstr);

    if (flag == 0) {
        if (strcasecmp(portstr, "any") == 0)
            s->flags |= SIG_FLAG_SP_ANY;

        r = DetectPortParse(de_ctx, &s->sp, (char *)portstr);
    } else if (flag == 1) {
        if (strcasecmp(portstr, "any") == 0)
            s->flags |= SIG_FLAG_DP_ANY;

        r = DetectPortParse(de_ctx, &s->dp, (char *)portstr);
    }

    if (r < 0)
        return -1;

    return 0;
}

/** \retval 1 valid
 *  \retval 0 invalid
 */
static int SigParseActionRejectValidate(const char *action)
{
#ifdef HAVE_LIBNET11
#if defined HAVE_LIBCAP_NG && !defined HAVE_LIBNET_CAPABILITIES
    if (sc_set_caps == TRUE) {
        SCLogError(SC_ERR_LIBNET11_INCOMPATIBLE_WITH_LIBCAP_NG, "Libnet 1.1 is "
            "incompatible with POSIX based capabilities with privs dropping. "
            "For rejects to work, run as root/super user.");
        return 0;
    }
#endif
#else /* no libnet 1.1 */
    SCLogError(SC_ERR_LIBNET_REQUIRED_FOR_ACTION, "Libnet 1.1.x is "
            "required for action \"%s\" but is not compiled into Suricata",
            action);
    return 0;
#endif
    return 1;
}

/**
 * \brief Parses the action that has been used by the Signature and allots it
 *        to its Signature instance.
 *
 * \param s      Pointer to the Signature instance to which the action belongs.
 * \param action Pointer to the action string used by the Signature.
 *
 * \retval  0 On successfully parsing the action string and adding it to the
 *            Signature.
 * \retval -1 On failure.
 */
static int SigParseAction(Signature *s, const char *action)
{
    if (strcasecmp(action, "alert") == 0) {
        s->action = ACTION_ALERT;
    } else if (strcasecmp(action, "drop") == 0) {
        s->action = ACTION_DROP;
    } else if (strcasecmp(action, "pass") == 0) {
        s->action = ACTION_PASS;
    } else if (strcasecmp(action, "reject") == 0 ||
               strcasecmp(action, "rejectsrc") == 0)
    {
        if (!(SigParseActionRejectValidate(action)))
            return -1;
        s->action = ACTION_REJECT|ACTION_DROP;
    } else if (strcasecmp(action, "rejectdst") == 0) {
        if (!(SigParseActionRejectValidate(action)))
            return -1;
        s->action = ACTION_REJECT_DST|ACTION_DROP;
    } else if (strcasecmp(action, "rejectboth") == 0) {
        if (!(SigParseActionRejectValidate(action)))
            return -1;
        s->action = ACTION_REJECT_BOTH|ACTION_DROP;
    } else if (strcasecmp(action, "config") == 0) {
        s->action = ACTION_CONFIG;
        s->flags |= SIG_FLAG_NOALERT;
    } else {
        SCLogError(SC_ERR_INVALID_ACTION,"An invalid action \"%s\" was given",action);
        return -1;
    }
    return 0;
}

/**
 * \brief Parse the next token in rule.
 *
 * For rule parsing a token is considered to be a string of characters
 * separated by white space.
 *
 * \param input double pointer to input buffer, will be advanced as input is
 *     parsed.
 * \param output buffer to copy token into.
 * \param output_size length of output buffer.
 */
static inline int SigParseToken(char **input, char *output,
    const size_t output_size)
{
    size_t len = *input == NULL ? 0 : strlen(*input);

    if (!len) {
        return 0;
    }

    while (len && isblank(**input)) {
        (*input)++;
        len--;
    }

    char *endptr = strpbrk(*input, " \t\n\r");
    if (endptr != NULL) {
        *(endptr++) = '\0';
    }
    strlcpy(output, *input, output_size);
    *input = endptr;

    return 1;
}

/**
 * \brief Parse the next rule "list" token.
 *
 * Parses rule tokens that may be lists such as addresses and ports
 * handling the case when they may not be lists.
 *
 * \param input double pointer to input buffer, will be advanced as input is
 *     parsed.
 * \param output buffer to copy token into.
 * \param output_size length of output buffer.
 */
static inline int SigParseList(char **input, char *output,
    const size_t output_size)
{
    int in_list = 0;
    size_t len = *input != NULL ? strlen(*input) : 0;

    if (len == 0) {
        return 0;
    }

    while (len && isblank(**input)) {
        (*input)++;
        len--;
    }

    size_t i = 0;
    for (i = 0; i < len; i++) {
        char c = (*input)[i];
        if (c == '[') {
            in_list++;
        } else if (c == ']') {
            in_list--;
        } else if (c == ' ') {
            if (!in_list) {
                break;
            }
        }
    }
    if (i == len) {
        *input = NULL;
        return 0;
    }
    (*input)[i] = '\0';
    strlcpy(output, *input, output_size);
    *input = *input + i + 1;

    return 1;
}

/**
 *  \internal
 *  \brief split a signature string into a few blocks for further parsing
 */
static int SigParseBasics(DetectEngineCtx *de_ctx,
        Signature *s, const char *sigstr, SignatureParser *parser, uint8_t addrs_direction)
{
    char *index, dup[DETECT_MAX_RULE_SIZE];

    strlcpy(dup, sigstr, DETECT_MAX_RULE_SIZE);
    index = dup;

    /* Action. */
    SigParseToken(&index, parser->action, sizeof(parser->action));

    /* Protocol. */
    SigParseList(&index, parser->protocol, sizeof(parser->protocol));

    /* Source. */
    SigParseList(&index, parser->src, sizeof(parser->src));

    /* Source port(s). */
    SigParseList(&index, parser->sp, sizeof(parser->sp));

    /* Direction. */
    SigParseToken(&index, parser->direction, sizeof(parser->direction));

    /* Destination. */
    SigParseList(&index, parser->dst, sizeof(parser->dst));

    /* Destination port(s). */
    SigParseList(&index, parser->dp, sizeof(parser->dp));

    /* Options. */
    if (index == NULL) {
        SCLogError(SC_ERR_INVALID_RULE_ARGUMENT, "no rule options.");
        goto error;
    }
    while (isspace(*index) || *index == '(') {
        index++;
    }
    for (size_t i = strlen(index); i > 0; i--) {
        if (isspace(index[i - 1]) || index[i - 1] == ')') {
            index[i - 1] = '\0';
        } else {
            break;
        }
    }
    strlcpy(parser->opts, index, sizeof(parser->opts));

    /* Parse Action */
    if (SigParseAction(s, parser->action) < 0)
        goto error;

    if (SigParseProto(s, parser->protocol) < 0)
        goto error;

    if (strcmp(parser->direction, "<>") == 0) {
        s->init_data->init_flags |= SIG_FLAG_INIT_BIDIREC;
    } else if (strcmp(parser->direction, "->") != 0) {
        SCLogError(SC_ERR_INVALID_DIRECTION,
                "\"%s\" is not a valid direction modifier, "
                "\"->\" and \"<>\" are supported.", parser->direction);
        goto error;
    }

    /* Parse Address & Ports */
    if (SigParseAddress(de_ctx, s, parser->src, SIG_DIREC_SRC ^ addrs_direction) < 0)
       goto error;

    if (SigParseAddress(de_ctx, s, parser->dst, SIG_DIREC_DST ^ addrs_direction) < 0)
        goto error;

    /* By AWS - Traditionally we should be doing this only for tcp/udp/sctp,
     * but we do it for regardless of ip proto, since the dns/dnstcp/dnsudp
     * changes that we made sees to it that at this point of time we don't
     * set the ip proto for the sig.  We do it a bit later. */
    if (SigParsePort(de_ctx, s, parser->sp, SIG_DIREC_SRC ^ addrs_direction) < 0)
        goto error;
    if (SigParsePort(de_ctx, s, parser->dp, SIG_DIREC_DST ^ addrs_direction) < 0)
        goto error;

    return 0;

error:
    return -1;
}

/**
 *  \brief parse a signature
 *
 *  \param de_ctx detection engine ctx to add it to
 *  \param s memory structure to store the signature in
 *  \param sigstr the raw signature as a null terminated string
 *  \param addrs_direction direction (for bi-directional sigs)
 *
 *  \param -1 parse error
 *  \param 0 ok
 */
static int SigParse(DetectEngineCtx *de_ctx, Signature *s,
        const char *sigstr, uint8_t addrs_direction, SignatureParser *parser)
{
    SCEnter();

    if (!rs_check_utf8(sigstr)) {
        SCLogError(SC_ERR_RULE_INVALID_UTF8, "rule is not valid UTF-8");
        SCReturnInt(-1);
    }

    s->sig_str = SCStrdup(sigstr);
    if (unlikely(s->sig_str == NULL)) {
        SCReturnInt(-1);
    }

    int ret = SigParseBasics(de_ctx, s, sigstr, parser, addrs_direction);
    if (ret < 0) {
        SCLogDebug("SigParseBasics failed");
        SCReturnInt(-1);
    }

    /* we can have no options, so make sure we have them */
    if (strlen(parser->opts) > 0) {
        size_t buffer_size = strlen(parser->opts) + 1;
        char input[buffer_size];
        char output[buffer_size];
        memset(input, 0x00, buffer_size);
        memcpy(input, parser->opts, strlen(parser->opts)+1);

        /* loop the option parsing. Each run processes one option
         * and returns the rest of the option string through the
         * output variable. */
        do {
            memset(output, 0x00, buffer_size);
            ret = SigParseOptions(de_ctx, s, input, output, buffer_size);
            if (ret == 1) {
                memcpy(input, output, buffer_size);
            }

        } while (ret == 1);
    }

    DetectIPProtoRemoveAllSMs(de_ctx, s);

    SCReturnInt(ret);
}

Signature *SigAlloc (void)
{
    Signature *sig = SCMalloc(sizeof(Signature));
    if (unlikely(sig == NULL))
        return NULL;
    memset(sig, 0, sizeof(Signature));

    sig->init_data = SCCalloc(1, sizeof(SignatureInitData));
    if (sig->init_data == NULL) {
        SCFree(sig);
        return NULL;
    }
    sig->init_data->mpm_sm_list = -1;

    sig->init_data->smlists_array_size = DetectBufferTypeMaxId();
    SCLogDebug("smlists size %u", sig->init_data->smlists_array_size);
    sig->init_data->smlists = SCCalloc(sig->init_data->smlists_array_size, sizeof(SigMatch *));
    if (sig->init_data->smlists == NULL) {
        SCFree(sig->init_data);
        SCFree(sig);
        return NULL;
    }

    sig->init_data->smlists_tail = SCCalloc(sig->init_data->smlists_array_size, sizeof(SigMatch *));
    if (sig->init_data->smlists_tail == NULL) {
        SCFree(sig->init_data->smlists);
        SCFree(sig->init_data);
        SCFree(sig);
        return NULL;
    }

    /* assign it to -1, so that we can later check if the value has been
     * overwritten after the Signature has been parsed, and if it hasn't been
     * overwritten, we can then assign the default value of 3 */
    sig->prio = -1;

    sig->init_data->list = DETECT_SM_LIST_NOTSET;
    return sig;
}

/**
 * \internal
 * \brief Free Metadata list
 *
 * \param s Pointer to the signature
 */
static void SigMetadataFree(Signature *s)
{
    SCEnter();

    DetectMetadata *mdata = NULL;
    DetectMetadata *next_mdata = NULL;

    if (s == NULL || s->metadata == NULL) {
        SCReturn;
    }

    SCLogDebug("s %p, s->metadata %p", s, s->metadata);

    for (mdata = s->metadata->list; mdata != NULL;)   {
        next_mdata = mdata->next;
        DetectMetadataFree(mdata);
        mdata = next_mdata;
    }
    SCFree(s->metadata->json_str);
    SCFree(s->metadata);
    s->metadata = NULL;

    SCReturn;
}

/**
 * \internal
 * \brief Free Reference list
 *
 * \param s Pointer to the signature
 */
static void SigRefFree (Signature *s)
{
    SCEnter();

    DetectReference *ref = NULL;
    DetectReference *next_ref = NULL;

    if (s == NULL) {
        SCReturn;
    }

    SCLogDebug("s %p, s->references %p", s, s->references);

    for (ref = s->references; ref != NULL;)   {
        next_ref = ref->next;
        DetectReferenceFree(ref);
        ref = next_ref;
    }

    s->references = NULL;

    SCReturn;
}

static void SigMatchFreeArrays(DetectEngineCtx *de_ctx, Signature *s, int ctxs)
{
    if (s != NULL) {
        int type;
        for (type = 0; type < DETECT_SM_LIST_MAX; type++) {
            if (s->sm_arrays[type] != NULL) {
                if (ctxs) {
                    SigMatchData *smd = s->sm_arrays[type];
                    while(1) {
                        if (sigmatch_table[smd->type].Free != NULL) {
                            sigmatch_table[smd->type].Free(de_ctx, smd->ctx);
                        }
                        if (smd->is_last)
                            break;
                        smd++;
                    }
                }

                SCFree(s->sm_arrays[type]);
            }
        }
    }
}

void SigFree(DetectEngineCtx *de_ctx, Signature *s)
{
    if (s == NULL)
        return;

    if (s->cidr_dst != NULL)
        IPOnlyCIDRListFree(s->cidr_dst);

    if (s->cidr_src != NULL)
        IPOnlyCIDRListFree(s->cidr_src);

    int i;

    if (s->init_data && s->init_data->transforms.cnt) {
        for(i = 0; i < s->init_data->transforms.cnt; i++) {
            if (s->init_data->transforms.transforms[i].options) {
                int transform = s->init_data->transforms.transforms[i].transform;
                sigmatch_table[transform].Free(
                        de_ctx, s->init_data->transforms.transforms[i].options);
                s->init_data->transforms.transforms[i].options = NULL;
            }
        }
    }
    if (s->init_data) {
        const int nlists = s->init_data->smlists_array_size;
        for (i = 0; i < nlists; i++) {
            SigMatch *sm = s->init_data->smlists[i];
            while (sm != NULL) {
                SigMatch *nsm = sm->next;
                SigMatchFree(de_ctx, sm);
                sm = nsm;
            }
        }
    }
    SigMatchFreeArrays(de_ctx, s, (s->init_data == NULL));
    if (s->init_data) {
        SCFree(s->init_data->smlists);
        SCFree(s->init_data->smlists_tail);
        SCFree(s->init_data);
        s->init_data = NULL;
    }

    if (s->sp != NULL) {
        DetectPortCleanupList(NULL, s->sp);
    }
    if (s->dp != NULL) {
        DetectPortCleanupList(NULL, s->dp);
    }

    if (s->msg != NULL)
        SCFree(s->msg);

    if (s->addr_src_match4 != NULL) {
        SCFree(s->addr_src_match4);
    }
    if (s->addr_dst_match4 != NULL) {
        SCFree(s->addr_dst_match4);
    }
    if (s->addr_src_match6 != NULL) {
        SCFree(s->addr_src_match6);
    }
    if (s->addr_dst_match6 != NULL) {
        SCFree(s->addr_dst_match6);
    }
    if (s->sig_str != NULL) {
        SCFree(s->sig_str);
    }

    SigRefFree(s);
    SigMetadataFree(s);

    DetectEngineAppInspectionEngineSignatureFree(de_ctx, s);

    SCFree(s);
}

int DetectSignatureAddTransform(Signature *s, int transform, void *options)
{
    /* we only support buffers */
    if (s->init_data->list == 0) {
        SCReturnInt(-1);
    }
    if (!s->init_data->list_set) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "transforms must directly follow stickybuffers");
        SCReturnInt(-1);
    }
    if (s->init_data->transforms.cnt >= DETECT_TRANSFORMS_MAX) {
        SCReturnInt(-1);
    }

    s->init_data->transforms.transforms[s->init_data->transforms.cnt].transform = transform;
    s->init_data->transforms.transforms[s->init_data->transforms.cnt].options = options;

    s->init_data->transforms.cnt++;
    SCLogDebug("Added transform #%d [%s]",
            s->init_data->transforms.cnt,
            s->sig_str);

    SCReturnInt(0);
}

int DetectSignatureSetAppProto(Signature *s, AppProto alproto)
{
    if (alproto == ALPROTO_UNKNOWN ||
        alproto >= ALPROTO_FAILED) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "invalid alproto %u", alproto);
        return -1;
    }

    if (s->alproto != ALPROTO_UNKNOWN && !AppProtoEquals(s->alproto, alproto)) {
        if (AppProtoEquals(alproto, s->alproto)) {
            // happens if alproto = HTTP_ANY and s->alproto = HTTP1
            // in this case, we must keep the most restrictive HTTP1
            alproto = s->alproto;
        } else {
            SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS,
                    "can't set rule app proto to %s: already set to %s", AppProtoToString(alproto),
                    AppProtoToString(s->alproto));
            return -1;
        }
    }

    if (AppLayerProtoDetectGetProtoName(alproto) == NULL) {
        SCLogError(SC_ERR_INVALID_ARGUMENT, "disabled alproto %s, rule can never match",
                AppProtoToString(alproto));
        return -1;
    }
    s->alproto = alproto;
    s->flags |= SIG_FLAG_APPLAYER;
    return 0;
}

/**
 *  \internal
 *  \brief build address match array for cache efficient matching
 *
 *  \param s the signature
 */
static void SigBuildAddressMatchArray(Signature *s)
{
    /* source addresses */
    uint16_t cnt = 0;
    uint16_t idx = 0;
    DetectAddress *da = s->init_data->src->ipv4_head;
    for ( ; da != NULL; da = da->next) {
        cnt++;
    }
    if (cnt > 0) {
        s->addr_src_match4 = SCMalloc(cnt * sizeof(DetectMatchAddressIPv4));
        if (s->addr_src_match4 == NULL) {
            exit(EXIT_FAILURE);
        }

        for (da = s->init_data->src->ipv4_head; da != NULL; da = da->next) {
            s->addr_src_match4[idx].ip = SCNtohl(da->ip.addr_data32[0]);
            s->addr_src_match4[idx].ip2 = SCNtohl(da->ip2.addr_data32[0]);
            idx++;
        }
        s->addr_src_match4_cnt = cnt;
    }

    /* destination addresses */
    cnt = 0;
    idx = 0;
    da = s->init_data->dst->ipv4_head;
    for ( ; da != NULL; da = da->next) {
        cnt++;
    }
    if (cnt > 0) {
        s->addr_dst_match4 = SCMalloc(cnt * sizeof(DetectMatchAddressIPv4));
        if (s->addr_dst_match4 == NULL) {
            exit(EXIT_FAILURE);
        }

        for (da = s->init_data->dst->ipv4_head; da != NULL; da = da->next) {
            s->addr_dst_match4[idx].ip = SCNtohl(da->ip.addr_data32[0]);
            s->addr_dst_match4[idx].ip2 = SCNtohl(da->ip2.addr_data32[0]);
            idx++;
        }
        s->addr_dst_match4_cnt = cnt;
    }

    /* source addresses IPv6 */
    cnt = 0;
    idx = 0;
    da = s->init_data->src->ipv6_head;
    for ( ; da != NULL; da = da->next) {
        cnt++;
    }
    if (cnt > 0) {
        s->addr_src_match6 = SCMalloc(cnt * sizeof(DetectMatchAddressIPv6));
        if (s->addr_src_match6 == NULL) {
            exit(EXIT_FAILURE);
        }

        for (da = s->init_data->src->ipv6_head; da != NULL; da = da->next) {
            s->addr_src_match6[idx].ip[0] = SCNtohl(da->ip.addr_data32[0]);
            s->addr_src_match6[idx].ip[1] = SCNtohl(da->ip.addr_data32[1]);
            s->addr_src_match6[idx].ip[2] = SCNtohl(da->ip.addr_data32[2]);
            s->addr_src_match6[idx].ip[3] = SCNtohl(da->ip.addr_data32[3]);
            s->addr_src_match6[idx].ip2[0] = SCNtohl(da->ip2.addr_data32[0]);
            s->addr_src_match6[idx].ip2[1] = SCNtohl(da->ip2.addr_data32[1]);
            s->addr_src_match6[idx].ip2[2] = SCNtohl(da->ip2.addr_data32[2]);
            s->addr_src_match6[idx].ip2[3] = SCNtohl(da->ip2.addr_data32[3]);
            idx++;
        }
        s->addr_src_match6_cnt = cnt;
    }

    /* destination addresses IPv6 */
    cnt = 0;
    idx = 0;
    da = s->init_data->dst->ipv6_head;
    for ( ; da != NULL; da = da->next) {
        cnt++;
    }
    if (cnt > 0) {
        s->addr_dst_match6 = SCMalloc(cnt * sizeof(DetectMatchAddressIPv6));
        if (s->addr_dst_match6 == NULL) {
            exit(EXIT_FAILURE);
        }

        for (da = s->init_data->dst->ipv6_head; da != NULL; da = da->next) {
            s->addr_dst_match6[idx].ip[0] = SCNtohl(da->ip.addr_data32[0]);
            s->addr_dst_match6[idx].ip[1] = SCNtohl(da->ip.addr_data32[1]);
            s->addr_dst_match6[idx].ip[2] = SCNtohl(da->ip.addr_data32[2]);
            s->addr_dst_match6[idx].ip[3] = SCNtohl(da->ip.addr_data32[3]);
            s->addr_dst_match6[idx].ip2[0] = SCNtohl(da->ip2.addr_data32[0]);
            s->addr_dst_match6[idx].ip2[1] = SCNtohl(da->ip2.addr_data32[1]);
            s->addr_dst_match6[idx].ip2[2] = SCNtohl(da->ip2.addr_data32[2]);
            s->addr_dst_match6[idx].ip2[3] = SCNtohl(da->ip2.addr_data32[3]);
            idx++;
        }
        s->addr_dst_match6_cnt = cnt;
    }
}

static int SigMatchListLen(SigMatch *sm)
{
    int len = 0;
    for (; sm != NULL; sm = sm->next)
        len++;

    return len;
}

/** \brief convert SigMatch list to SigMatchData array
 *  \note ownership of sm->ctx is transferred to smd->ctx
 */
SigMatchData* SigMatchList2DataArray(SigMatch *head)
{
    int len = SigMatchListLen(head);
    if (len == 0)
        return NULL;

    SigMatchData *smd = (SigMatchData *)SCCalloc(len, sizeof(SigMatchData));
    if (smd == NULL) {
        FatalError(SC_ERR_FATAL, "initializing the detection engine failed");
    }
    SigMatchData *out = smd;

    /* Copy sm type and Context into array */
    SigMatch *sm = head;
    for (; sm != NULL; sm = sm->next, smd++) {
        smd->type = sm->type;
        smd->ctx = sm->ctx;
        sm->ctx = NULL; // SigMatch no longer owns the ctx
        smd->is_last = (sm->next == NULL);
    }
    return out;
}

/**
 *  \internal
 *  \brief validate a just parsed signature for internal inconsistencies
 *
 *  \param s just parsed signature
 *
 *  \retval 0 invalid
 *  \retval 1 valid
 */
static int SigValidate(DetectEngineCtx *de_ctx, Signature *s)
{
    uint32_t sig_flags = 0;
    SigMatch *sm;
    const int nlists = s->init_data->smlists_array_size;

    SCEnter();

    /* check for sticky buffers that were set w/o matches
     * e.g. alert ... (file_data; sid:1;) */
    if (s->init_data->list != DETECT_SM_LIST_NOTSET) {
        if (s->init_data->list >= (int)s->init_data->smlists_array_size ||
                s->init_data->smlists[s->init_data->list] == NULL) {
            SCLogError(SC_ERR_INVALID_SIGNATURE,
                    "rule %u setup buffer %s but didn't add matches to it", s->id,
                    DetectEngineBufferTypeGetNameById(de_ctx, s->init_data->list));
            SCReturnInt(0);
        }
    }

    /* run buffer type validation callbacks if any */
    if (s->init_data->smlists[DETECT_SM_LIST_PMATCH]) {
        if (!DetectContentPMATCHValidateCallback(s))
            SCReturnInt(0);
    }

    struct BufferVsDir {
        int ts;
        int tc;
    } bufdir[nlists];
    memset(&bufdir, 0, nlists * sizeof(struct BufferVsDir));

    int x;
    for (x = 0; x < nlists; x++) {
        if (s->init_data->smlists[x]) {
            const DetectEngineAppInspectionEngine *app = de_ctx->app_inspect_engines;
            for ( ; app != NULL; app = app->next) {
                if (app->sm_list == x &&
                        (AppProtoEquals(s->alproto, app->alproto) || s->alproto == 0)) {
                    SCLogDebug("engine %s dir %d alproto %d",
                            DetectEngineBufferTypeGetNameById(de_ctx, app->sm_list), app->dir,
                            app->alproto);

                    bufdir[x].ts += (app->dir == 0);
                    bufdir[x].tc += (app->dir == 1);
                }
            }

            if (!DetectEngineBufferRunValidateCallback(de_ctx, x, s, &de_ctx->sigerror)) {
                SCReturnInt(0);
            }
        }
    }

    int ts_excl = 0;
    int tc_excl = 0;
    int dir_amb = 0;
    for (x = 0; x < nlists; x++) {
        if (bufdir[x].ts == 0 && bufdir[x].tc == 0)
            continue;
        ts_excl += (bufdir[x].ts > 0 && bufdir[x].tc == 0);
        tc_excl += (bufdir[x].ts == 0 && bufdir[x].tc > 0);
        dir_amb += (bufdir[x].ts > 0 && bufdir[x].tc > 0);

        SCLogDebug("%s/%d: %d/%d", DetectEngineBufferTypeGetNameById(de_ctx, x), x, bufdir[x].ts,
                bufdir[x].tc);
    }
    if (ts_excl && tc_excl) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "rule %u mixes keywords with conflicting directions", s->id);
        SCReturnInt(0);
    } else if (ts_excl) {
        SCLogDebug("%u: implied rule direction is toserver", s->id);
        if (DetectFlowSetupImplicit(s, SIG_FLAG_TOSERVER) < 0) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "rule %u mixes keywords with conflicting directions", s->id);
            SCReturnInt(0);
        }
    } else if (tc_excl) {
        SCLogDebug("%u: implied rule direction is toclient", s->id);
        if (DetectFlowSetupImplicit(s, SIG_FLAG_TOCLIENT) < 0) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "rule %u mixes keywords with conflicting directions", s->id);
            SCReturnInt(0);
        }
    } else if (dir_amb) {
        SCLogDebug("%u: rule direction cannot be deduced from keywords", s->id);
    }

    if ((s->flags & SIG_FLAG_REQUIRE_PACKET) &&
        (s->flags & SIG_FLAG_REQUIRE_STREAM)) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "can't mix packet keywords with "
                   "tcp-stream or flow:only_stream.  Invalidating signature.");
        SCReturnInt(0);
    }

#if 0 // TODO figure out why this is even necessary
    if ((s->init_data->smlists[DETECT_SM_LIST_FILEDATA] != NULL && s->alproto == ALPROTO_SMTP) ||
        s->init_data->smlists[DETECT_SM_LIST_UMATCH] != NULL ||
        s->init_data->smlists[DETECT_SM_LIST_HRUDMATCH] != NULL ||
        s->init_data->smlists[DETECT_SM_LIST_HCBDMATCH] != NULL ||
        s->init_data->smlists[DETECT_SM_LIST_HUADMATCH] != NULL) {
        sig_flags |= SIG_FLAG_TOSERVER;
        s->flags |= SIG_FLAG_TOSERVER;
        s->flags &= ~SIG_FLAG_TOCLIENT;
    }
    if ((s->init_data->smlists[DETECT_SM_LIST_FILEDATA] != NULL && s->alproto == ALPROTO_HTTP1) ||
        s->init_data->smlists[DETECT_SM_LIST_HSMDMATCH] != NULL ||
        s->init_data->smlists[DETECT_SM_LIST_HSCDMATCH] != NULL) {
        sig_flags |= SIG_FLAG_TOCLIENT;
        s->flags |= SIG_FLAG_TOCLIENT;
        s->flags &= ~SIG_FLAG_TOSERVER;
    }
#endif
    if ((sig_flags & (SIG_FLAG_TOCLIENT | SIG_FLAG_TOSERVER)) == (SIG_FLAG_TOCLIENT | SIG_FLAG_TOSERVER)) {
        SCLogError(SC_ERR_INVALID_SIGNATURE,"You seem to have mixed keywords "
                   "that require inspection in both directions.  Atm we only "
                   "support keywords in one direction within a rule.");
        SCReturnInt(0);
    }

    bool has_pmatch = false;
    bool has_frame = false;
    bool has_app = false;
    bool has_pkt = false;

    for (int i = 0; i < nlists; i++) {
        if (s->init_data->smlists[i] == NULL)
            continue;
        has_pmatch |= (i == DETECT_SM_LIST_PMATCH);

        const DetectBufferType *b = DetectEngineBufferTypeGetById(de_ctx, i);
        if (b == NULL)
            continue;

        has_frame |= b->frame;
        has_app |= (b->frame == false && b->packet == false);
        has_pkt |= b->packet;
    }
    if (has_pmatch && has_frame) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "can't mix pure content and frame inspection");
        SCReturnInt(0);
    }
    if (has_app && has_frame) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "can't mix app-layer buffer and frame inspection");
        SCReturnInt(0);
    }
    if (has_pkt && has_frame) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "can't mix pkt buffer and frame inspection");
        SCReturnInt(0);
    }

    if (s->flags & SIG_FLAG_REQUIRE_PACKET) {
        for (int i = 0; i < nlists; i++) {
            if (s->init_data->smlists[i] == NULL)
                continue;
            if (!(DetectEngineBufferTypeGetNameById(de_ctx, i)))
                continue;

            if (!(DetectEngineBufferTypeSupportsPacketGetById(de_ctx, i))) {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "Signature combines packet "
                        "specific matches (like dsize, flags, ttl) with stream / "
                        "state matching by matching on app layer proto (like using "
                        "http_* keywords).");
                SCReturnInt(0);
            }
        }
    }

    /* TCP: corner cases:
     * - pkt vs stream vs depth/offset
     * - pkt vs stream vs stream_size
     */
    if (s->proto.proto[IPPROTO_TCP / 8] & (1 << (IPPROTO_TCP % 8))) {
        if (s->init_data->smlists[DETECT_SM_LIST_PMATCH]) {
            if (!(s->flags & (SIG_FLAG_REQUIRE_PACKET | SIG_FLAG_REQUIRE_STREAM))) {
                s->flags |= SIG_FLAG_REQUIRE_STREAM;
                sm = s->init_data->smlists[DETECT_SM_LIST_PMATCH];
                while (sm != NULL) {
                    if (sm->type == DETECT_CONTENT &&
                            (((DetectContentData *)(sm->ctx))->flags &
                             (DETECT_CONTENT_DEPTH | DETECT_CONTENT_OFFSET))) {
                        s->flags |= SIG_FLAG_REQUIRE_PACKET;
                        break;
                    }
                    sm = sm->next;
                }
                /* if stream_size is in use, also inspect packets */
                sm = s->init_data->smlists[DETECT_SM_LIST_MATCH];
                while (sm != NULL) {
                    if (sm->type == DETECT_STREAM_SIZE) {
                        s->flags |= SIG_FLAG_REQUIRE_PACKET;
                        break;
                    }
                    sm = sm->next;
                }
            }
        }
    }

    if (s->init_data->smlists[DETECT_SM_LIST_BASE64_DATA] != NULL) {
        int list;
        uint16_t idx = s->init_data->smlists[DETECT_SM_LIST_BASE64_DATA]->idx;
        for (list = 0; list < nlists; list++) {
            if (list == DETECT_SM_LIST_POSTMATCH ||
                list == DETECT_SM_LIST_TMATCH ||
                list == DETECT_SM_LIST_SUPPRESS ||
                list == DETECT_SM_LIST_THRESHOLD)
            {
                continue;
            }

            if (list != DETECT_SM_LIST_BASE64_DATA &&
                s->init_data->smlists[list] != NULL) {
                if (s->init_data->smlists[list]->idx > idx) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "Rule buffer "
                        "cannot be reset after base64_data.");
                    SCReturnInt(0);
                }
            }
        }
    }

#ifdef HAVE_LUA
    DetectLuaPostSetup(s);
#endif

#ifdef DEBUG
    int i;
    for (i = 0; i < nlists; i++) {
        if (s->init_data->smlists[i] != NULL) {
            for (sm = s->init_data->smlists[i]; sm != NULL; sm = sm->next) {
                BUG_ON(sm == sm->prev);
                BUG_ON(sm == sm->next);
            }
        }
    }
#endif

    if ((s->flags & SIG_FLAG_FILESTORE) || s->file_flags != 0 ||
        (s->init_data->init_flags & SIG_FLAG_INIT_FILEDATA)) {
        if (s->alproto != ALPROTO_UNKNOWN &&
                !AppLayerParserSupportsFiles(IPPROTO_TCP, s->alproto))
        {
            SCLogError(SC_ERR_NO_FILES_FOR_PROTOCOL, "protocol %s doesn't "
                    "support file matching", AppProtoToString(s->alproto));
            SCReturnInt(0);
        }
        if (s->alproto == ALPROTO_HTTP2 && (s->file_flags & FILE_SIG_NEED_FILENAME)) {
            SCLogError(SC_ERR_NO_FILES_FOR_PROTOCOL,
                    "protocol HTTP2 doesn't support file name matching");
            SCReturnInt(0);
        }

        if (s->alproto == ALPROTO_HTTP1 || s->alproto == ALPROTO_HTTP) {
            AppLayerHtpNeedFileInspection();
        }
    }
    if (s->init_data->init_flags & SIG_FLAG_INIT_DCERPC) {
        if (s->alproto != ALPROTO_UNKNOWN && s->alproto != ALPROTO_DCERPC &&
                s->alproto != ALPROTO_SMB) {
            SCLogError(SC_ERR_NO_FILES_FOR_PROTOCOL, "protocol %s doesn't support DCERPC keyword",
                    AppProtoToString(s->alproto));
            SCReturnInt(0);
        }
    }
    if (s->id == 0) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "Signature missing required value \"sid\".");
        SCReturnInt(0);
    }
    SCReturnInt(1);
}

/**
 * \internal
 * \brief Helper function for SigInit().
 */
static Signature *SigInitHelper(DetectEngineCtx *de_ctx, const char *sigstr,
                                uint8_t dir)
{
    SignatureParser parser;
    memset(&parser, 0x00, sizeof(parser));

    Signature *sig = SigAlloc();
    if (sig == NULL)
        goto error;

    /* default gid to 1 */
    sig->gid = 1;

    int ret = SigParse(de_ctx, sig, sigstr, dir, &parser);
    if (ret == -3) {
        de_ctx->sigerror_silent = true;
        de_ctx->sigerror_ok = true;
        goto error;
    }
    else if (ret == -2) {
        de_ctx->sigerror_silent = true;
        goto error;
    } else if (ret < 0) {
        goto error;
    }

    /* signature priority hasn't been overwritten.  Using default priority */
    if (sig->prio == -1)
        sig->prio = DETECT_DEFAULT_PRIO;

    sig->num = de_ctx->signum;
    de_ctx->signum++;

    if (sig->alproto != ALPROTO_UNKNOWN) {
        int override_needed = 0;
        if (sig->proto.flags & DETECT_PROTO_ANY) {
            sig->proto.flags &= ~DETECT_PROTO_ANY;
            memset(sig->proto.proto, 0x00, sizeof(sig->proto.proto));
            override_needed = 1;
        } else {
            override_needed = 1;
            size_t s = 0;
            for (s = 0; s < sizeof(sig->proto.proto); s++) {
                if (sig->proto.proto[s] != 0x00) {
                    override_needed = 0;
                    break;
                }
            }
        }

        /* at this point if we had alert ip and the ip proto was not
         * overridden, we use the ip proto that has been configured
         * against the app proto in use. */
        if (override_needed)
            AppLayerProtoDetectSupportedIpprotos(sig->alproto, sig->proto.proto);
    }

    ret = DetectAppLayerEventPrepare(de_ctx, sig);
    if (ret == -3) {
        de_ctx->sigerror_silent = true;
        de_ctx->sigerror_ok = true;
        goto error;
    }
    else if (ret == -2) {
        de_ctx->sigerror_silent = true;
        goto error;
    } else if (ret < 0) {
        goto error;
    }

    /* set the packet and app layer flags, but only if the
     * app layer flag wasn't already set in which case we
     * only consider the app layer */
    if (!(sig->flags & SIG_FLAG_APPLAYER)) {
        if (sig->init_data->smlists[DETECT_SM_LIST_MATCH] != NULL) {
            SigMatch *sm = sig->init_data->smlists[DETECT_SM_LIST_MATCH];
            for ( ; sm != NULL; sm = sm->next) {
                if (sigmatch_table[sm->type].Match != NULL)
                    sig->init_data->init_flags |= SIG_FLAG_INIT_PACKET;
            }
        } else {
            sig->init_data->init_flags |= SIG_FLAG_INIT_PACKET;
        }
    }

    if (!(sig->init_data->init_flags & SIG_FLAG_INIT_FLOW)) {
        if ((sig->flags & (SIG_FLAG_TOSERVER|SIG_FLAG_TOCLIENT)) == 0) {
            sig->flags |= SIG_FLAG_TOSERVER;
            sig->flags |= SIG_FLAG_TOCLIENT;
        }
    }

    SCLogDebug("sig %"PRIu32" SIG_FLAG_APPLAYER: %s, SIG_FLAG_PACKET: %s",
        sig->id, sig->flags & SIG_FLAG_APPLAYER ? "set" : "not set",
        sig->init_data->init_flags & SIG_FLAG_INIT_PACKET ? "set" : "not set");

    SigBuildAddressMatchArray(sig);

    /* run buffer type callbacks if any */
    for (uint32_t x = 0; x < sig->init_data->smlists_array_size; x++) {
        if (sig->init_data->smlists[x])
            DetectEngineBufferRunSetupCallback(de_ctx, x, sig);
    }

    /* validate signature, SigValidate will report the error reason */
    if (SigValidate(de_ctx, sig) == 0) {
        goto error;
    }

    /* check what the type of this sig is */
    SignatureSetType(de_ctx, sig);

    if (sig->flags & SIG_FLAG_IPONLY) {
        /* For IPOnly */
        if (IPOnlySigParseAddress(de_ctx, sig, parser.src, SIG_DIREC_SRC ^ dir) < 0)
            goto error;

        if (IPOnlySigParseAddress(de_ctx, sig, parser.dst, SIG_DIREC_DST ^ dir) < 0)
            goto error;
    }
    return sig;

error:
    if (sig != NULL) {
        SigFree(de_ctx, sig);
    }
    return NULL;
}

/**
 * \brief Checks if a signature has the same source and destination
 * \param s parsed signature
 *
 *  \retval true if source and destination are the same, false otherwise
 */
static bool SigHasSameSourceAndDestination(const Signature *s)
{
    if (!(s->flags & SIG_FLAG_SP_ANY) || !(s->flags & SIG_FLAG_DP_ANY)) {
        if (!DetectPortListsAreEqual(s->sp, s->dp)) {
            return false;
        }
    }

    if (!(s->flags & SIG_FLAG_SRC_ANY) || !(s->flags & SIG_FLAG_DST_ANY)) {
        DetectAddress *src = s->init_data->src->ipv4_head;
        DetectAddress *dst = s->init_data->dst->ipv4_head;

        if (!DetectAddressListsAreEqual(src, dst)) {
            return false;
        }

        src = s->init_data->src->ipv6_head;
        dst = s->init_data->dst->ipv6_head;

        if (!DetectAddressListsAreEqual(src, dst)) {
            return false;
        }
    }

    return true;
}

/**
 * \brief Parses a signature and adds it to the Detection Engine Context.
 *
 * \param de_ctx Pointer to the Detection Engine Context.
 * \param sigstr Pointer to a character string containing the signature to be
 *               parsed.
 *
 * \retval Pointer to the Signature instance on success; NULL on failure.
 */
Signature *SigInit(DetectEngineCtx *de_ctx, const char *sigstr)
{
    SCEnter();

    uint32_t oldsignum = de_ctx->signum;
    de_ctx->sigerror_silent = false;

    Signature *sig;

    if ((sig = SigInitHelper(de_ctx, sigstr, SIG_DIREC_NORMAL)) == NULL) {
        goto error;
    }

    if (sig->init_data->init_flags & SIG_FLAG_INIT_BIDIREC) {
        if (SigHasSameSourceAndDestination(sig)) {
            SCLogInfo("Rule with ID %u is bidirectional, but source and destination are the same, "
                "treating the rule as unidirectional", sig->id);

            sig->init_data->init_flags &= ~SIG_FLAG_INIT_BIDIREC;
        } else {
            sig->next = SigInitHelper(de_ctx, sigstr, SIG_DIREC_SWITCHED);
            if (sig->next == NULL) {
                goto error;
            }
        }
    }

    SCReturnPtr(sig, "Signature");

error:
    if (sig != NULL) {
        SigFree(de_ctx, sig);
    }
    /* if something failed, restore the old signum count
     * since we didn't install it */
    de_ctx->signum = oldsignum;

    SCReturnPtr(NULL, "Signature");
}

/**
 * \brief The hash free function to be the used by the hash table -
 *        DetectEngineCtx->dup_sig_hash_table.
 *
 * \param data    Pointer to the data, in our case SigDuplWrapper to be freed.
 */
static void DetectParseDupSigFreeFunc(void *data)
{
    if (data != NULL)
        SCFree(data);

    return;
}

/**
 * \brief The hash function to be the used by the hash table -
 *        DetectEngineCtx->dup_sig_hash_table.
 *
 * \param ht      Pointer to the hash table.
 * \param data    Pointer to the data, in our case SigDuplWrapper.
 * \param datalen Not used in our case.
 *
 * \retval sw->s->id The generated hash value.
 */
static uint32_t DetectParseDupSigHashFunc(HashListTable *ht, void *data, uint16_t datalen)
{
    SigDuplWrapper *sw = (SigDuplWrapper *)data;

    return (sw->s->id % ht->array_size);
}

/**
 * \brief The Compare function to be used by the  hash table -
 *        DetectEngineCtx->dup_sig_hash_table.
 *
 * \param data1 Pointer to the first SigDuplWrapper.
 * \param len1  Not used.
 * \param data2 Pointer to the second SigDuplWrapper.
 * \param len2  Not used.
 *
 * \retval 1 If the 2 SigDuplWrappers sent as args match.
 * \retval 0 If the 2 SigDuplWrappers sent as args do not match.
 */
static char DetectParseDupSigCompareFunc(void *data1, uint16_t len1, void *data2,
                                  uint16_t len2)
{
    SigDuplWrapper *sw1 = (SigDuplWrapper *)data1;
    SigDuplWrapper *sw2 = (SigDuplWrapper *)data2;

    if (sw1 == NULL || sw2 == NULL ||
        sw1->s == NULL || sw2->s == NULL)
        return 0;

    /* sid and gid match required */
    if (sw1->s->id == sw2->s->id && sw1->s->gid == sw2->s->gid) return 1;

    return 0;
}

/**
 * \brief Initializes the hash table that is used to cull duplicate sigs.
 *
 * \param de_ctx Pointer to the detection engine context.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
int DetectParseDupSigHashInit(DetectEngineCtx *de_ctx)
{
    de_ctx->dup_sig_hash_table = HashListTableInit(15000,
                                                   DetectParseDupSigHashFunc,
                                                   DetectParseDupSigCompareFunc,
                                                   DetectParseDupSigFreeFunc);
    if (de_ctx->dup_sig_hash_table == NULL)
        return -1;

    return 0;
}

/**
 * \brief Frees the hash table that is used to cull duplicate sigs.
 *
 * \param de_ctx Pointer to the detection engine context that holds this table.
 */
void DetectParseDupSigHashFree(DetectEngineCtx *de_ctx)
{
    if (de_ctx->dup_sig_hash_table != NULL)
        HashListTableFree(de_ctx->dup_sig_hash_table);

    de_ctx->dup_sig_hash_table = NULL;

    return;
}

/**
 * \brief Check if a signature is a duplicate.
 *
 *        There are 3 types of return values for this function.
 *
 *        - 0, which indicates that the Signature is not a duplicate
 *          and has to be added to the detection engine list.
 *        - 1, Signature is duplicate, and the existing signature in
 *          the list shouldn't be replaced with this duplicate.
 *        - 2, Signature is duplicate, and the existing signature in
 *          the list should be replaced with this duplicate.
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param sig    Pointer to the Signature that has to be checked.
 *
 * \retval 2 If Signature is duplicate and the existing signature in
 *           the list should be chucked out and replaced with this.
 * \retval 1 If Signature is duplicate, and should be chucked out.
 * \retval 0 If Signature is not a duplicate.
 */
static inline int DetectEngineSignatureIsDuplicate(DetectEngineCtx *de_ctx,
                                                   Signature *sig)
{
    /* we won't do any NULL checks on the args */

    /* return value */
    int ret = 0;

    SigDuplWrapper *sw_dup = NULL;
    SigDuplWrapper *sw = NULL;

    /* used for making a duplicate_sig_hash_table entry */
    sw = SCMalloc(sizeof(SigDuplWrapper));
    if (unlikely(sw == NULL)) {
        exit(EXIT_FAILURE);
    }
    memset(sw, 0, sizeof(SigDuplWrapper));
    sw->s = sig;

    /* check if we have a duplicate entry for this signature */
    sw_dup = HashListTableLookup(de_ctx->dup_sig_hash_table, (void *)sw, 0);
    /* we don't have a duplicate entry for this sig */
    if (sw_dup == NULL) {
        /* add it to the hash table */
        HashListTableAdd(de_ctx->dup_sig_hash_table, (void *)sw, 0);

        /* add the s_prev entry for the previously loaded sw in the hash_table */
        if (de_ctx->sig_list != NULL) {
            SigDuplWrapper *sw_old = NULL;
            SigDuplWrapper sw_tmp;
            memset(&sw_tmp, 0, sizeof(SigDuplWrapper));

            /* the topmost sig would be the last loaded sig */
            sw_tmp.s = de_ctx->sig_list;
            sw_old = HashListTableLookup(de_ctx->dup_sig_hash_table,
                                         (void *)&sw_tmp, 0);
            /* sw_old == NULL case is impossible */
            sw_old->s_prev = sig;
        }

        ret = 0;
        goto end;
    }

    /* if we have reached here we have a duplicate entry for this signature.
     * Check the signature revision.  Store the signature with the latest rev
     * and discard the other one */
    if (sw->s->rev <= sw_dup->s->rev) {
        ret = 1;
        SCFree(sw);
        sw = NULL;
        goto end;
    }

    /* the new sig is of a newer revision than the one that is already in the
     * list.  Remove the old sig from the list */
    if (sw_dup->s_prev == NULL) {
        SigDuplWrapper sw_temp;
        memset(&sw_temp, 0, sizeof(SigDuplWrapper));
        if (sw_dup->s->init_data->init_flags & SIG_FLAG_INIT_BIDIREC) {
            sw_temp.s = sw_dup->s->next->next;
            de_ctx->sig_list = sw_dup->s->next->next;
            SigFree(de_ctx, sw_dup->s->next);
        } else {
            sw_temp.s = sw_dup->s->next;
            de_ctx->sig_list = sw_dup->s->next;
        }
        SigDuplWrapper *sw_next = NULL;
        if (sw_temp.s != NULL) {
            sw_next = HashListTableLookup(de_ctx->dup_sig_hash_table,
                                          (void *)&sw_temp, 0);
            sw_next->s_prev = sw_dup->s_prev;
        }
        SigFree(de_ctx, sw_dup->s);
    } else {
        SigDuplWrapper sw_temp;
        memset(&sw_temp, 0, sizeof(SigDuplWrapper));
        if (sw_dup->s->init_data->init_flags & SIG_FLAG_INIT_BIDIREC) {
            sw_temp.s = sw_dup->s->next->next;
            /* If previous signature is bidirectional,
             * it has 2 items in the linked list.
             * So we need to change next->next instead of next
             */
            if (sw_dup->s_prev->init_data->init_flags & SIG_FLAG_INIT_BIDIREC) {
                sw_dup->s_prev->next->next = sw_dup->s->next->next;
            } else {
                sw_dup->s_prev->next = sw_dup->s->next->next;
            }
            SigFree(de_ctx, sw_dup->s->next);
        } else {
            sw_temp.s = sw_dup->s->next;
            if (sw_dup->s_prev->init_data->init_flags & SIG_FLAG_INIT_BIDIREC) {
                sw_dup->s_prev->next->next = sw_dup->s->next;
            } else {
                sw_dup->s_prev->next = sw_dup->s->next;
            }
        }
        SigDuplWrapper *sw_next = NULL;
        if (sw_temp.s != NULL) {
            sw_next = HashListTableLookup(de_ctx->dup_sig_hash_table,
                                          (void *)&sw_temp, 0);
            sw_next->s_prev = sw_dup->s_prev;;
        }
        SigFree(de_ctx, sw_dup->s);
    }

    /* make changes to the entry to reflect the presence of the new sig */
    sw_dup->s = sig;
    sw_dup->s_prev = NULL;

    if (de_ctx->sig_list != NULL) {
        SigDuplWrapper sw_tmp;
        memset(&sw_tmp, 0, sizeof(SigDuplWrapper));
        sw_tmp.s = de_ctx->sig_list;
        SigDuplWrapper *sw_old = HashListTableLookup(de_ctx->dup_sig_hash_table,
                                                     (void *)&sw_tmp, 0);
        if (sw_old->s != sw_dup->s) {
            // Link on top of the list if there was another element
            sw_old->s_prev = sig;
        }
    }

    /* this is duplicate, but a duplicate that replaced the existing sig entry */
    ret = 2;

    SCFree(sw);

end:
    return ret;
}

/**
 * \brief Parse and append a Signature into the Detection Engine Context
 *        signature list.
 *
 *        If the signature is bidirectional it should append two signatures
 *        (with the addresses switched) into the list.  Also handle duplicate
 *        signatures.  In case of duplicate sigs, use the ones that have the
 *        latest revision.  We use the sid and the msg to identify duplicate
 *        sigs.  If 2 sigs have the same sid and gid, they are duplicates.
 *
 * \param de_ctx Pointer to the Detection Engine Context.
 * \param sigstr Pointer to a character string containing the signature to be
 *               parsed.
 * \param sig_file Pointer to a character string containing the filename from
 *                 which signature is read
 * \param lineno Line number from where signature is read
 *
 * \retval Pointer to the head Signature in the detection engine ctx sig_list
 *         on success; NULL on failure.
 */
Signature *DetectEngineAppendSig(DetectEngineCtx *de_ctx, const char *sigstr)
{
    Signature *sig = SigInit(de_ctx, sigstr);
    if (sig == NULL) {
        return NULL;
    }

    /* checking for the status of duplicate signature */
    int dup_sig = DetectEngineSignatureIsDuplicate(de_ctx, sig);
    /* a duplicate signature that should be chucked out.  Check the previously
     * called function details to understand the different return values */
    if (dup_sig == 1) {
        SCLogError(SC_ERR_DUPLICATE_SIG, "Duplicate signature \"%s\"", sigstr);
        goto error;
    } else if (dup_sig == 2) {
        SCLogWarning(SC_ERR_DUPLICATE_SIG, "Signature with newer revision,"
                " so the older sig replaced by this new signature \"%s\"",
                sigstr);
    }

    if (sig->init_data->init_flags & SIG_FLAG_INIT_BIDIREC) {
        if (sig->next != NULL) {
            sig->next->next = de_ctx->sig_list;
        } else {
            goto error;
        }
    } else {
        /* if this sig is the first one, sig_list should be null */
        sig->next = de_ctx->sig_list;
    }

    de_ctx->sig_list = sig;

    /**
     * In DetectEngineAppendSig(), the signatures are prepended and we always return the first one
     * so if the signature is bidirectional, the returned sig will point through "next" ptr
     * to the cloned signatures with the switched addresses
     */
    return (dup_sig == 0 || dup_sig == 2) ? sig : NULL;

error:
    /* free the 2nd sig bidir may have set up */
    if (sig != NULL && sig->next != NULL) {
        SigFree(de_ctx, sig->next);
        sig->next = NULL;
    }
    if (sig != NULL) {
        SigFree(de_ctx, sig);
    }
    return NULL;
}

static DetectParseRegex *g_detect_parse_regex_list = NULL;

int DetectParsePcreExec(
        DetectParseRegex *parse_regex, const char *str, int start_offset, int options)
{
    return pcre2_match(parse_regex->regex, (PCRE2_SPTR8)str, strlen(str), options, start_offset,
            parse_regex->match, NULL);
}

void DetectParseFreeRegex(DetectParseRegex *r)
{
    if (r->regex) {
        pcre2_code_free(r->regex);
    }
    if (r->context) {
        pcre2_match_context_free(r->context);
    }
    if (r->match) {
        pcre2_match_data_free(r->match);
    }
}

void DetectParseFreeRegexes(void)
{
    DetectParseRegex *r = g_detect_parse_regex_list;
    while (r) {
        DetectParseRegex *next = r->next;

        DetectParseFreeRegex(r);

        SCFree(r);
        r = next;
    }
    g_detect_parse_regex_list = NULL;
}

/** \brief add regex and/or study to at exit free list
 */
void DetectParseRegexAddToFreeList(DetectParseRegex *detect_parse)
{
    DetectParseRegex *r = SCCalloc(1, sizeof(*r));
    if (r == NULL) {
        FatalError(SC_ERR_MEM_ALLOC, "failed to alloc memory for pcre free list");
    }
    r->regex = detect_parse->regex;
    r->match = detect_parse->match;
    r->next = g_detect_parse_regex_list;
    g_detect_parse_regex_list = r;
}

bool DetectSetupParseRegexesOpts(const char *parse_str, DetectParseRegex *detect_parse, int opts)
{
    int en;
    PCRE2_SIZE eo;

    detect_parse->regex =
            pcre2_compile((PCRE2_SPTR8)parse_str, PCRE2_ZERO_TERMINATED, opts, &en, &eo, NULL);
    if (detect_parse->regex == NULL) {
        PCRE2_UCHAR errbuffer[256];
        pcre2_get_error_message(en, errbuffer, sizeof(errbuffer));
        SCLogError(SC_ERR_PCRE_COMPILE,
                "pcre compile of \"%s\" failed at "
                "offset %d: %s",
                parse_str, en, errbuffer);
        return false;
    }
    detect_parse->match = pcre2_match_data_create_from_pattern(detect_parse->regex, NULL);

    DetectParseRegexAddToFreeList(detect_parse);

    return true;
}

DetectParseRegex *DetectSetupPCRE2(const char *parse_str, int opts)
{
    int en;
    PCRE2_SIZE eo;
    DetectParseRegex *detect_parse = SCCalloc(1, sizeof(DetectParseRegex));
    if (detect_parse == NULL) {
        return NULL;
    }

    detect_parse->regex =
            pcre2_compile((PCRE2_SPTR8)parse_str, PCRE2_ZERO_TERMINATED, opts, &en, &eo, NULL);
    if (detect_parse->regex == NULL) {
        PCRE2_UCHAR errbuffer[256];
        pcre2_get_error_message(en, errbuffer, sizeof(errbuffer));
        SCLogError(SC_ERR_PCRE_COMPILE,
                "pcre2 compile of \"%s\" failed at "
                "offset %d: %s",
                parse_str, (int)eo, errbuffer);
        SCFree(detect_parse);
        return NULL;
    }
    detect_parse->match = pcre2_match_data_create_from_pattern(detect_parse->regex, NULL);

    detect_parse->next = g_detect_parse_regex_list;
    g_detect_parse_regex_list = detect_parse;
    return detect_parse;
}

int SC_Pcre2SubstringCopy(
        pcre2_match_data *match_data, uint32_t number, PCRE2_UCHAR *buffer, PCRE2_SIZE *bufflen)
{
    int r = pcre2_substring_copy_bynumber(match_data, number, buffer, bufflen);
    if (r == PCRE2_ERROR_UNSET) {
        buffer[0] = 0;
        *bufflen = 0;
        return 0;
    }
    return r;
}

int SC_Pcre2SubstringGet(
        pcre2_match_data *match_data, uint32_t number, PCRE2_UCHAR **bufferptr, PCRE2_SIZE *bufflen)
{
    int r = pcre2_substring_get_bynumber(match_data, number, bufferptr, bufflen);
    if (r == PCRE2_ERROR_UNSET) {
        *bufferptr = NULL;
        *bufflen = 0;
        return 0;
    }
    return r;
}

void DetectSetupParseRegexes(const char *parse_str, DetectParseRegex *detect_parse)
{
    if (!DetectSetupParseRegexesOpts(parse_str, detect_parse, 0)) {
        FatalError(SC_ERR_PCRE_COMPILE, "pcre compile and study failed");
    }
}


/*
 * TESTS
 */

#ifdef UNITTESTS
static int SigParseTest01 (void)
{
    int result = 1;
    Signature *sig = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    sig = SigInit(de_ctx, "alert tcp 1.2.3.4 any -> !1.2.3.4 any (msg:\"SigParseTest01\"; sid:1;)");
    if (sig == NULL)
        result = 0;

end:
    if (sig != NULL) SigFree(de_ctx, sig);
    if (de_ctx != NULL) DetectEngineCtxFree(de_ctx);
    return result;
}

static int SigParseTest02 (void)
{
    int result = 0;
    Signature *sig = NULL;
    DetectPort *port = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();

    if (de_ctx == NULL)
        goto end;

    FILE *fd = SCClassConfGenerateValidDummyClassConfigFD01();
    SCClassConfLoadClassficationConfigFile(de_ctx, fd);

    sig = SigInit(de_ctx, "alert tcp any !21:902 -> any any (msg:\"ET MALWARE Suspicious 220 Banner on Local Port\"; content:\"220\"; offset:0; depth:4; pcre:\"/220[- ]/\"; sid:2003055; rev:4;)");
    if (sig == NULL) {
        goto end;
    }

    int r = DetectPortParse(de_ctx, &port, "0:20");
    if (r < 0)
        goto end;

    if (DetectPortCmp(sig->sp, port) == PORT_EQ) {
        result = 1;
    } else {
        DetectPortPrint(port); printf(" != "); DetectPortPrint(sig->sp); printf(": ");
    }

end:
    if (port != NULL)
        DetectPortCleanupList(de_ctx, port);
    if (sig != NULL)
        SigFree(de_ctx, sig);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test SigParseTest03 test for invalid direction operator in rule
 */
static int SigParseTest03 (void)
{
    int result = 1;
    Signature *sig = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    sig = SigInit(de_ctx, "alert tcp 1.2.3.4 any <- !1.2.3.4 any (msg:\"SigParseTest03\"; sid:1;)");
    if (sig != NULL) {
        result = 0;
        printf("expected NULL got sig ptr %p: ",sig);
    }

end:
    if (sig != NULL) SigFree(de_ctx, sig);
    if (de_ctx != NULL) DetectEngineCtxFree(de_ctx);
    return result;
}

static int SigParseTest04 (void)
{
    int result = 1;
    Signature *sig = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    sig = SigInit(de_ctx, "alert tcp 1.2.3.4 1024: -> !1.2.3.4 1024: (msg:\"SigParseTest04\"; sid:1;)");
    if (sig == NULL)
        result = 0;

end:
    if (sig != NULL) SigFree(de_ctx, sig);
    if (de_ctx != NULL) DetectEngineCtxFree(de_ctx);
    return result;
}

/** \test Port validation */
static int SigParseTest05 (void)
{
    int result = 0;
    Signature *sig = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    sig = SigInit(de_ctx, "alert tcp 1.2.3.4 1024:65536 -> !1.2.3.4 any (msg:\"SigParseTest05\"; sid:1;)");
    if (sig == NULL) {
        result = 1;
    } else {
        printf("signature didn't fail to parse as we expected: ");
    }

end:
    if (sig != NULL) SigFree(de_ctx, sig);
    if (de_ctx != NULL) DetectEngineCtxFree(de_ctx);
    return result;
}

/** \test Parsing bug debugging at 2010-03-18 */
static int SigParseTest06 (void)
{
    int result = 0;
    Signature *sig = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    sig = SigInit(de_ctx, "alert tcp any any -> any any (flow:to_server; content:\"GET\"; nocase; http_method; uricontent:\"/uri/\"; nocase; content:\"Host|3A| abc\"; nocase; sid:1; rev:1;)");
    if (sig != NULL) {
        result = 1;
    } else {
        printf("signature failed to parse: ");
    }

end:
    if (sig != NULL)
        SigFree(de_ctx, sig);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Parsing duplicate sigs.
 */
static int SigParseTest07(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (msg:\"boo\"; sid:1; rev:1;)");
    DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (msg:\"boo\"; sid:1; rev:1;)");

    result = (de_ctx->sig_list != NULL && de_ctx->sig_list->next == NULL);

end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Parsing duplicate sigs.
 */
static int SigParseTest08(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (msg:\"boo\"; sid:1; rev:1;)");
    DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (msg:\"boo\"; sid:1; rev:2;)");

    result = (de_ctx->sig_list != NULL && de_ctx->sig_list->next == NULL &&
              de_ctx->sig_list->rev == 2);

end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Parsing duplicate sigs.
 */
static int SigParseTest09(void)
{
    int result = 1;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (msg:\"boo\"; sid:1; rev:1;)");
    DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (msg:\"boo\"; sid:1; rev:2;)");
    DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (msg:\"boo\"; sid:1; rev:6;)");
    DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (msg:\"boo\"; sid:1; rev:4;)");
    DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (msg:\"boo\"; sid:2; rev:2;)");
    result &= (de_ctx->sig_list != NULL && de_ctx->sig_list->id == 2 &&
               de_ctx->sig_list->rev == 2);
    if (result == 0)
        goto end;
    result &= (de_ctx->sig_list->next != NULL && de_ctx->sig_list->next->id == 1 &&
               de_ctx->sig_list->next->rev == 6);
    if (result == 0)
        goto end;

    DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (msg:\"boo\"; sid:2; rev:1;)");
    result &= (de_ctx->sig_list != NULL && de_ctx->sig_list->id == 2 &&
               de_ctx->sig_list->rev == 2);
    if (result == 0)
        goto end;
    result &= (de_ctx->sig_list->next != NULL && de_ctx->sig_list->next->id == 1 &&
               de_ctx->sig_list->next->rev == 6);
    if (result == 0)
        goto end;

    DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (msg:\"boo\"; sid:2; rev:4;)");
    result &= (de_ctx->sig_list != NULL && de_ctx->sig_list->id == 2 &&
               de_ctx->sig_list->rev == 4);
    if (result == 0)
        goto end;
    result &= (de_ctx->sig_list->next != NULL && de_ctx->sig_list->next->id == 1 &&
               de_ctx->sig_list->next->rev == 6);
    if (result == 0)
        goto end;

end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Parsing duplicate sigs.
 */
static int SigParseTest10(void)
{
    int result = 1;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (msg:\"boo\"; sid:1; rev:1;)");
    DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (msg:\"boo\"; sid:2; rev:1;)");
    DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (msg:\"boo\"; sid:3; rev:1;)");
    DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (msg:\"boo\"; sid:4; rev:1;)");
    DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (msg:\"boo\"; sid:5; rev:1;)");
    DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (msg:\"boo\"; sid:3; rev:2;)");
    DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (msg:\"boo\"; sid:2; rev:2;)");

    result &= ((de_ctx->sig_list->id == 2) &&
               (de_ctx->sig_list->next->id == 3) &&
               (de_ctx->sig_list->next->next->id == 5) &&
               (de_ctx->sig_list->next->next->next->id == 4) &&
               (de_ctx->sig_list->next->next->next->next->id == 1));

end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test Parsing sig with trailing space(s) as reported by
 *       Morgan Cox on oisf-users.
 */
static int SigParseTest11(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    Signature *s = NULL;

    s = DetectEngineAppendSig(de_ctx,
            "drop tcp any any -> any 80 (msg:\"Snort_Inline is blocking the http link\"; sid:1;) ");
    if (s == NULL) {
        printf("sig 1 didn't parse: ");
        goto end;
    }

    s = DetectEngineAppendSig(de_ctx, "drop tcp any any -> any 80 (msg:\"Snort_Inline is blocking "
                                      "the http link\"; sid:2;)            ");
    if (s == NULL) {
        printf("sig 2 didn't parse: ");
        goto end;
    }

    result = 1;
end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test file_data with rawbytes
 */
static int SigParseTest12(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    Signature *s = NULL;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (file_data; content:\"abc\"; rawbytes; sid:1;)");
    if (s != NULL) {
        printf("sig 1 should have given an error: ");
        goto end;
    }

    result = 1;
end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test packet/stream sig
 */
static int SigParseTest13(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    Signature *s = NULL;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (content:\"abc\"; sid:1;)");
    if (s == NULL) {
        printf("sig 1 invalidated: failure");
        goto end;
    }

    if (!(s->flags & SIG_FLAG_REQUIRE_STREAM)) {
        printf("sig doesn't have stream flag set\n");
        goto end;
    }

    if (s->flags & SIG_FLAG_REQUIRE_PACKET) {
        printf("sig has packet flag set\n");
        goto end;
    }

    result = 1;

end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test packet/stream sig
 */
static int SigParseTest14(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    Signature *s = NULL;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (content:\"abc\"; dsize:>0; sid:1;)");
    if (s == NULL) {
        printf("sig 1 invalidated: failure");
        goto end;
    }

    if (!(s->flags & SIG_FLAG_REQUIRE_PACKET)) {
        printf("sig doesn't have packet flag set\n");
        goto end;
    }

    if (s->flags & SIG_FLAG_REQUIRE_STREAM) {
        printf("sig has stream flag set\n");
        goto end;
    }

    result = 1;

end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test packet/stream sig
 */
static int SigParseTest15(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    Signature *s = NULL;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (content:\"abc\"; offset:5; sid:1;)");
    if (s == NULL) {
        printf("sig 1 invalidated: failure");
        goto end;
    }

    if (!(s->flags & SIG_FLAG_REQUIRE_PACKET)) {
        printf("sig doesn't have packet flag set\n");
        goto end;
    }

    if (!(s->flags & SIG_FLAG_REQUIRE_STREAM)) {
        printf("sig doesn't have stream flag set\n");
        goto end;
    }

    result = 1;

end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test packet/stream sig
 */
static int SigParseTest16(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    Signature *s = NULL;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (content:\"abc\"; depth:5; sid:1;)");
    if (s == NULL) {
        printf("sig 1 invalidated: failure");
        goto end;
    }

    if (!(s->flags & SIG_FLAG_REQUIRE_PACKET)) {
        printf("sig doesn't have packet flag set\n");
        goto end;
    }

    if (!(s->flags & SIG_FLAG_REQUIRE_STREAM)) {
        printf("sig doesn't have stream flag set\n");
        goto end;
    }

    result = 1;

end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test packet/stream sig
 */
static int SigParseTest17(void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    Signature *s = NULL;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (content:\"abc\"; offset:1; depth:5; sid:1;)");
    if (s == NULL) {
        printf("sig 1 invalidated: failure");
        goto end;
    }

    if (!(s->flags & SIG_FLAG_REQUIRE_PACKET)) {
        printf("sig doesn't have packet flag set\n");
        goto end;
    }

    if (!(s->flags & SIG_FLAG_REQUIRE_STREAM)) {
        printf("sig doesn't have stream flag set\n");
        goto end;
    }

    result = 1;

end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/** \test sid value too large. Bug #779 */
static int SigParseTest18 (void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    if (DetectEngineAppendSig(de_ctx, "alert tcp 1.2.3.4 any -> !1.2.3.4 any (msg:\"SigParseTest01\"; sid:99999999999999999999;)") != NULL)
        goto end;

    result = 1;
end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/** \test gid value too large. Related to bug #779 */
static int SigParseTest19 (void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    if (DetectEngineAppendSig(de_ctx, "alert tcp 1.2.3.4 any -> !1.2.3.4 any (msg:\"SigParseTest01\"; sid:1; gid:99999999999999999999;)") != NULL)
        goto end;

    result = 1;
end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/** \test rev value too large. Related to bug #779 */
static int SigParseTest20 (void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    if (DetectEngineAppendSig(de_ctx, "alert tcp 1.2.3.4 any -> !1.2.3.4 any (msg:\"SigParseTest01\"; sid:1; rev:99999999999999999999;)") != NULL)
        goto end;

    result = 1;
end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/** \test address parsing */
static int SigParseTest21 (void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    if (DetectEngineAppendSig(de_ctx, "alert tcp [1.2.3.4, 1.2.3.5] any -> !1.2.3.4 any (sid:1;)") == NULL)
        goto end;

    result = 1;
end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/** \test address parsing */
static int SigParseTest22 (void)
{
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    if (DetectEngineAppendSig(de_ctx, "alert tcp [10.10.10.0/24, !10.10.10.247] any -> [10.10.10.0/24, !10.10.10.247] any (sid:1;)") == NULL)
        goto end;

    result = 1;
end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test rule ending in carriage return
 */
static int SigParseTest23(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *s = NULL;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (content:\"abc\"; offset:1; depth:5; sid:1;)\r");
    FAIL_IF_NULL(s);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

/** \test Direction operator validation (invalid) */
static int SigParseBidirecTest06 (void)
{
    int result = 1;
    Signature *sig = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    sig = DetectEngineAppendSig(de_ctx, "alert tcp 192.168.1.1 any - 192.168.1.5 any (msg:\"SigParseBidirecTest05\"; sid:1;)");
    if (sig == NULL)
        result = 1;

end:
    if (sig != NULL) SigFree(de_ctx, sig);
    if (de_ctx != NULL) DetectEngineCtxFree(de_ctx);
    return result;
}

/** \test Direction operator validation (invalid) */
static int SigParseBidirecTest07 (void)
{
    int result = 1;
    Signature *sig = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    sig = DetectEngineAppendSig(de_ctx, "alert tcp 192.168.1.1 any <- 192.168.1.5 any (msg:\"SigParseBidirecTest05\"; sid:1;)");
    if (sig == NULL)
        result = 1;

end:
    if (sig != NULL) SigFree(de_ctx, sig);
    if (de_ctx != NULL) DetectEngineCtxFree(de_ctx);
    return result;
}

/** \test Direction operator validation (invalid) */
static int SigParseBidirecTest08 (void)
{
    int result = 1;
    Signature *sig = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    sig = DetectEngineAppendSig(de_ctx, "alert tcp 192.168.1.1 any < 192.168.1.5 any (msg:\"SigParseBidirecTest05\"; sid:1;)");
    if (sig == NULL)
        result = 1;

end:
    if (sig != NULL) SigFree(de_ctx, sig);
    if (de_ctx != NULL) DetectEngineCtxFree(de_ctx);
    return result;
}

/** \test Direction operator validation (invalid) */
static int SigParseBidirecTest09 (void)
{
    int result = 1;
    Signature *sig = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    sig = DetectEngineAppendSig(de_ctx, "alert tcp 192.168.1.1 any > 192.168.1.5 any (msg:\"SigParseBidirecTest05\"; sid:1;)");
    if (sig == NULL)
        result = 1;

end:
    if (sig != NULL) SigFree(de_ctx, sig);
    if (de_ctx != NULL) DetectEngineCtxFree(de_ctx);
    return result;
}

/** \test Direction operator validation (invalid) */
static int SigParseBidirecTest10 (void)
{
    int result = 1;
    Signature *sig = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    sig = DetectEngineAppendSig(de_ctx, "alert tcp 192.168.1.1 any -< 192.168.1.5 any (msg:\"SigParseBidirecTest05\"; sid:1;)");
    if (sig == NULL)
        result = 1;

end:
    if (sig != NULL) SigFree(de_ctx, sig);
    if (de_ctx != NULL) DetectEngineCtxFree(de_ctx);
    return result;
}

/** \test Direction operator validation (invalid) */
static int SigParseBidirecTest11 (void)
{
    int result = 1;
    Signature *sig = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    sig = DetectEngineAppendSig(de_ctx, "alert tcp 192.168.1.1 any >- 192.168.1.5 any (msg:\"SigParseBidirecTest05\"; sid:1;)");
    if (sig == NULL)
        result = 1;

end:
    if (sig != NULL) SigFree(de_ctx, sig);
    if (de_ctx != NULL) DetectEngineCtxFree(de_ctx);
    return result;
}

/** \test Direction operator validation (invalid) */
static int SigParseBidirecTest12 (void)
{
    int result = 1;
    Signature *sig = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    sig = DetectEngineAppendSig(de_ctx, "alert tcp 192.168.1.1 any >< 192.168.1.5 any (msg:\"SigParseBidirecTest05\"; sid:1;)");
    if (sig == NULL)
        result = 1;

end:
    if (sig != NULL) SigFree(de_ctx, sig);
    if (de_ctx != NULL) DetectEngineCtxFree(de_ctx);
    return result;
}

/** \test Direction operator validation (valid) */
static int SigParseBidirecTest13 (void)
{
    int result = 1;
    Signature *sig = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    sig = DetectEngineAppendSig(de_ctx, "alert tcp 192.168.1.1 any <> 192.168.1.5 any (msg:\"SigParseBidirecTest05\"; sid:1;)");
    if (sig != NULL)
        result = 1;

end:
    if (de_ctx != NULL) DetectEngineCtxFree(de_ctx);
    return result;
}

/** \test Direction operator validation (valid) */
static int SigParseBidirecTest14 (void)
{
    int result = 1;
    Signature *sig = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    sig = DetectEngineAppendSig(de_ctx, "alert tcp 192.168.1.1 any -> 192.168.1.5 any (msg:\"SigParseBidirecTest05\"; sid:1;)");
    if (sig != NULL)
        result = 1;

end:
    if (de_ctx != NULL) DetectEngineCtxFree(de_ctx);
    return result;
}

/** \test Ensure that we don't set bidirectional in a
 *         normal (one direction) Signature
 */
static int SigTestBidirec01 (void)
{
    Signature *sig = NULL;
    int result = 0;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    sig = DetectEngineAppendSig(de_ctx, "alert tcp 1.2.3.4 1024:65535 -> !1.2.3.4 any (msg:\"SigTestBidirec01\"; sid:1;)");
    if (sig == NULL)
        goto end;
    if (sig->next != NULL)
        goto end;
    if (sig->init_data->init_flags & SIG_FLAG_INIT_BIDIREC)
        goto end;
    if (de_ctx->signum != 1)
        goto end;

    result = 1;

end:
    if (de_ctx != NULL) {
        SigCleanSignatures(de_ctx);
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }
    return result;
}

/** \test Ensure that we set a bidirectional Signature correctly */
static int SigTestBidirec02 (void)
{
    int result = 0;
    Signature *sig = NULL;
    Signature *copy = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    sig = DetectEngineAppendSig(de_ctx, "alert tcp 1.2.3.4 1024:65535 <> !1.2.3.4 any (msg:\"SigTestBidirec02\"; sid:1;)");
    if (sig == NULL)
        goto end;
    if (de_ctx->sig_list != sig)
        goto end;
    if (!(sig->init_data->init_flags & SIG_FLAG_INIT_BIDIREC))
        goto end;
    if (sig->next == NULL)
        goto end;
    if (de_ctx->signum != 2)
        goto end;
    copy = sig->next;
    if (copy->next != NULL)
        goto end;
    if (!(copy->init_data->init_flags & SIG_FLAG_INIT_BIDIREC))
        goto end;

    result = 1;

end:
    if (de_ctx != NULL) {
        SigCleanSignatures(de_ctx);
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    return result;
}

/** \test Ensure that we set a bidirectional Signature correctly
*         and we install it with the rest of the signatures, checking
*         also that it match with the correct addr directions
*/
static int SigTestBidirec03 (void)
{
    int result = 0;
    Signature *sig = NULL;
    Packet *p = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    const char *sigs[3];
    sigs[0] = "alert tcp any any -> 192.168.1.1 any (msg:\"SigTestBidirec03 sid 1\"; sid:1;)";
    sigs[1] = "alert tcp any any <> 192.168.1.1 any (msg:\"SigTestBidirec03 sid 2 bidirectional\"; sid:2;)";
    sigs[2] = "alert tcp any any -> 192.168.1.1 any (msg:\"SigTestBidirec03 sid 3\"; sid:3;)";
    UTHAppendSigs(de_ctx, sigs, 3);

    /* Checking that bidirectional rules are set correctly */
    sig = de_ctx->sig_list;
    if (sig == NULL)
        goto end;
    if (sig->next == NULL)
        goto end;
    if (sig->next->next == NULL)
        goto end;
    if (sig->next->next->next == NULL)
        goto end;
    if (sig->next->next->next->next != NULL)
        goto end;
    if (de_ctx->signum != 4)
        goto end;

    uint8_t rawpkt1_ether[] = {
        0x00,0x50,0x56,0xea,0x00,0xbd,0x00,0x0c,
        0x29,0x40,0xc8,0xb5,0x08,0x00,0x45,0x00,
        0x01,0xa8,0xb9,0xbb,0x40,0x00,0x40,0x06,
        0xe0,0xbf,0xc0,0xa8,0x1c,0x83,0xc0,0xa8,
        0x01,0x01,0xb9,0x0a,0x00,0x50,0x6f,0xa2,
        0x92,0xed,0x7b,0xc1,0xd3,0x4d,0x50,0x18,
        0x16,0xd0,0xa0,0x6f,0x00,0x00,0x47,0x45,
        0x54,0x20,0x2f,0x20,0x48,0x54,0x54,0x50,
        0x2f,0x31,0x2e,0x31,0x0d,0x0a,0x48,0x6f,
        0x73,0x74,0x3a,0x20,0x31,0x39,0x32,0x2e,
        0x31,0x36,0x38,0x2e,0x31,0x2e,0x31,0x0d,
        0x0a,0x55,0x73,0x65,0x72,0x2d,0x41,0x67,
        0x65,0x6e,0x74,0x3a,0x20,0x4d,0x6f,0x7a,
        0x69,0x6c,0x6c,0x61,0x2f,0x35,0x2e,0x30,
        0x20,0x28,0x58,0x31,0x31,0x3b,0x20,0x55,
        0x3b,0x20,0x4c,0x69,0x6e,0x75,0x78,0x20,
        0x78,0x38,0x36,0x5f,0x36,0x34,0x3b,0x20,
        0x65,0x6e,0x2d,0x55,0x53,0x3b,0x20,0x72,
        0x76,0x3a,0x31,0x2e,0x39,0x2e,0x30,0x2e,
        0x31,0x34,0x29,0x20,0x47,0x65,0x63,0x6b,
        0x6f,0x2f,0x32,0x30,0x30,0x39,0x30,0x39,
        0x30,0x32,0x31,0x37,0x20,0x55,0x62,0x75,
        0x6e,0x74,0x75,0x2f,0x39,0x2e,0x30,0x34,
        0x20,0x28,0x6a,0x61,0x75,0x6e,0x74,0x79,
        0x29,0x20,0x46,0x69,0x72,0x65,0x66,0x6f,
        0x78,0x2f,0x33,0x2e,0x30,0x2e,0x31,0x34,
        0x0d,0x0a,0x41,0x63,0x63,0x65,0x70,0x74,
        0x3a,0x20,0x74,0x65,0x78,0x74,0x2f,0x68,
        0x74,0x6d,0x6c,0x2c,0x61,0x70,0x70,0x6c,
        0x69,0x63,0x61,0x74,0x69,0x6f,0x6e,0x2f,
        0x78,0x68,0x74,0x6d,0x6c,0x2b,0x78,0x6d,
        0x6c,0x2c,0x61,0x70,0x70,0x6c,0x69,0x63,
        0x61,0x74,0x69,0x6f,0x6e,0x2f,0x78,0x6d,
        0x6c,0x3b,0x71,0x3d,0x30,0x2e,0x39,0x2c,
        0x2a,0x2f,0x2a,0x3b,0x71,0x3d,0x30,0x2e,
        0x38,0x0d,0x0a,0x41,0x63,0x63,0x65,0x70,
        0x74,0x2d,0x4c,0x61,0x6e,0x67,0x75,0x61,
        0x67,0x65,0x3a,0x20,0x65,0x6e,0x2d,0x75,
        0x73,0x2c,0x65,0x6e,0x3b,0x71,0x3d,0x30,
        0x2e,0x35,0x0d,0x0a,0x41,0x63,0x63,0x65,
        0x70,0x74,0x2d,0x45,0x6e,0x63,0x6f,0x64,
        0x69,0x6e,0x67,0x3a,0x20,0x67,0x7a,0x69,
        0x70,0x2c,0x64,0x65,0x66,0x6c,0x61,0x74,
        0x65,0x0d,0x0a,0x41,0x63,0x63,0x65,0x70,
        0x74,0x2d,0x43,0x68,0x61,0x72,0x73,0x65,
        0x74,0x3a,0x20,0x49,0x53,0x4f,0x2d,0x38,
        0x38,0x35,0x39,0x2d,0x31,0x2c,0x75,0x74,
        0x66,0x2d,0x38,0x3b,0x71,0x3d,0x30,0x2e,
        0x37,0x2c,0x2a,0x3b,0x71,0x3d,0x30,0x2e,
        0x37,0x0d,0x0a,0x4b,0x65,0x65,0x70,0x2d,
        0x41,0x6c,0x69,0x76,0x65,0x3a,0x20,0x33,
        0x30,0x30,0x0d,0x0a,0x43,0x6f,0x6e,0x6e,
        0x65,0x63,0x74,0x69,0x6f,0x6e,0x3a,0x20,
        0x6b,0x65,0x65,0x70,0x2d,0x61,0x6c,0x69,
        0x76,0x65,0x0d,0x0a,0x0d,0x0a }; /* end rawpkt1_ether */

    FlowInitConfig(FLOW_QUIET);
    p = UTHBuildPacketFromEth(rawpkt1_ether, sizeof(rawpkt1_ether));
    if (p == NULL) {
        SCLogDebug("Error building packet");
        goto end;
    }
    UTHMatchPackets(de_ctx, &p, 1);

    uint32_t sids[3] = {1, 2, 3};
    uint32_t results[3] = {1, 1, 1};
    result = UTHCheckPacketMatchResults(p, sids, results, 1);

end:
    if (p != NULL) {
        PACKET_RECYCLE(p);
        SCFree(p);
    }
    FlowShutdown();
    return result;
}

/** \test Ensure that we set a bidirectional Signature correctly
*         and we install it with the rest of the signatures, checking
*         also that it match with the correct addr directions
*/
static int SigTestBidirec04 (void)
{
    int result = 0;
    Signature *sig = NULL;
    Packet *p = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    sig = DetectEngineAppendSig(de_ctx, "alert tcp 192.168.1.1 any -> any any (msg:\"SigTestBidirec03 sid 1\"; sid:1;)");
    if (sig == NULL)
        goto end;
    sig = DetectEngineAppendSig(de_ctx, "alert tcp 192.168.1.1 any <> any any (msg:\"SigTestBidirec03 sid 2 bidirectional\"; sid:2;)");
    if (sig == NULL)
        goto end;
    if ( !(sig->init_data->init_flags & SIG_FLAG_INIT_BIDIREC))
        goto end;
    if (sig->next == NULL)
        goto end;
    if (sig->next->next == NULL)
        goto end;
    if (sig->next->next->next != NULL)
        goto end;
    if (de_ctx->signum != 3)
        goto end;

    sig = DetectEngineAppendSig(de_ctx, "alert tcp 192.168.1.1 any -> any any (msg:\"SigTestBidirec03 sid 3\"; sid:3;)");
    if (sig == NULL)
        goto end;
    if (sig->next == NULL)
        goto end;
    if (sig->next->next == NULL)
        goto end;
    if (sig->next->next->next == NULL)
        goto end;
    if (sig->next->next->next->next != NULL)
        goto end;
    if (de_ctx->signum != 4)
        goto end;

    uint8_t rawpkt1_ether[] = {
        0x00,0x50,0x56,0xea,0x00,0xbd,0x00,0x0c,
        0x29,0x40,0xc8,0xb5,0x08,0x00,0x45,0x00,
        0x01,0xa8,0xb9,0xbb,0x40,0x00,0x40,0x06,
        0xe0,0xbf,0xc0,0xa8,0x1c,0x83,0xc0,0xa8,
        0x01,0x01,0xb9,0x0a,0x00,0x50,0x6f,0xa2,
        0x92,0xed,0x7b,0xc1,0xd3,0x4d,0x50,0x18,
        0x16,0xd0,0xa0,0x6f,0x00,0x00,0x47,0x45,
        0x54,0x20,0x2f,0x20,0x48,0x54,0x54,0x50,
        0x2f,0x31,0x2e,0x31,0x0d,0x0a,0x48,0x6f,
        0x73,0x74,0x3a,0x20,0x31,0x39,0x32,0x2e,
        0x31,0x36,0x38,0x2e,0x31,0x2e,0x31,0x0d,
        0x0a,0x55,0x73,0x65,0x72,0x2d,0x41,0x67,
        0x65,0x6e,0x74,0x3a,0x20,0x4d,0x6f,0x7a,
        0x69,0x6c,0x6c,0x61,0x2f,0x35,0x2e,0x30,
        0x20,0x28,0x58,0x31,0x31,0x3b,0x20,0x55,
        0x3b,0x20,0x4c,0x69,0x6e,0x75,0x78,0x20,
        0x78,0x38,0x36,0x5f,0x36,0x34,0x3b,0x20,
        0x65,0x6e,0x2d,0x55,0x53,0x3b,0x20,0x72,
        0x76,0x3a,0x31,0x2e,0x39,0x2e,0x30,0x2e,
        0x31,0x34,0x29,0x20,0x47,0x65,0x63,0x6b,
        0x6f,0x2f,0x32,0x30,0x30,0x39,0x30,0x39,
        0x30,0x32,0x31,0x37,0x20,0x55,0x62,0x75,
        0x6e,0x74,0x75,0x2f,0x39,0x2e,0x30,0x34,
        0x20,0x28,0x6a,0x61,0x75,0x6e,0x74,0x79,
        0x29,0x20,0x46,0x69,0x72,0x65,0x66,0x6f,
        0x78,0x2f,0x33,0x2e,0x30,0x2e,0x31,0x34,
        0x0d,0x0a,0x41,0x63,0x63,0x65,0x70,0x74,
        0x3a,0x20,0x74,0x65,0x78,0x74,0x2f,0x68,
        0x74,0x6d,0x6c,0x2c,0x61,0x70,0x70,0x6c,
        0x69,0x63,0x61,0x74,0x69,0x6f,0x6e,0x2f,
        0x78,0x68,0x74,0x6d,0x6c,0x2b,0x78,0x6d,
        0x6c,0x2c,0x61,0x70,0x70,0x6c,0x69,0x63,
        0x61,0x74,0x69,0x6f,0x6e,0x2f,0x78,0x6d,
        0x6c,0x3b,0x71,0x3d,0x30,0x2e,0x39,0x2c,
        0x2a,0x2f,0x2a,0x3b,0x71,0x3d,0x30,0x2e,
        0x38,0x0d,0x0a,0x41,0x63,0x63,0x65,0x70,
        0x74,0x2d,0x4c,0x61,0x6e,0x67,0x75,0x61,
        0x67,0x65,0x3a,0x20,0x65,0x6e,0x2d,0x75,
        0x73,0x2c,0x65,0x6e,0x3b,0x71,0x3d,0x30,
        0x2e,0x35,0x0d,0x0a,0x41,0x63,0x63,0x65,
        0x70,0x74,0x2d,0x45,0x6e,0x63,0x6f,0x64,
        0x69,0x6e,0x67,0x3a,0x20,0x67,0x7a,0x69,
        0x70,0x2c,0x64,0x65,0x66,0x6c,0x61,0x74,
        0x65,0x0d,0x0a,0x41,0x63,0x63,0x65,0x70,
        0x74,0x2d,0x43,0x68,0x61,0x72,0x73,0x65,
        0x74,0x3a,0x20,0x49,0x53,0x4f,0x2d,0x38,
        0x38,0x35,0x39,0x2d,0x31,0x2c,0x75,0x74,
        0x66,0x2d,0x38,0x3b,0x71,0x3d,0x30,0x2e,
        0x37,0x2c,0x2a,0x3b,0x71,0x3d,0x30,0x2e,
        0x37,0x0d,0x0a,0x4b,0x65,0x65,0x70,0x2d,
        0x41,0x6c,0x69,0x76,0x65,0x3a,0x20,0x33,
        0x30,0x30,0x0d,0x0a,0x43,0x6f,0x6e,0x6e,
        0x65,0x63,0x74,0x69,0x6f,0x6e,0x3a,0x20,
        0x6b,0x65,0x65,0x70,0x2d,0x61,0x6c,0x69,
        0x76,0x65,0x0d,0x0a,0x0d,0x0a }; /* end rawpkt1_ether */

    p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;
    DecodeThreadVars dtv;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx;

    memset(&th_v, 0, sizeof(th_v));

    FlowInitConfig(FLOW_QUIET);
    DecodeEthernet(&th_v, &dtv, p, rawpkt1_ether, sizeof(rawpkt1_ether));
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    /* At this point we have a list of 4 signatures. The last one
       is a copy of the second one. If we receive a packet
       with source 192.168.1.1 80, all the sids should match */

    SigGroupBuild(de_ctx);
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    /* only sid 2 should match with a packet going to 192.168.1.1 port 80 */
    if (PacketAlertCheck(p, 1) <= 0 && PacketAlertCheck(p, 3) <= 0 &&
        PacketAlertCheck(p, 2) == 1) {
        result = 1;
    }

    if (p != NULL) {
        PACKET_RECYCLE(p);
    }
    FlowShutdown();
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);

end:
    if (de_ctx != NULL) {
        SigCleanSignatures(de_ctx);
        SigGroupCleanup(de_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    if (p != NULL)
        SCFree(p);
    return result;
}

/**
 * \test check that we don't allow invalid negation options
 */
static int SigParseTestNegation01 (void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;
    Signature *s = DetectEngineAppendSig(de_ctx, "alert tcp !any any -> any any (sid:1;)");
    FAIL_IF_NOT_NULL(s);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test check that we don't allow invalid negation options
 */
static int SigParseTestNegation02 (void)
{
    int result = 0;
    DetectEngineCtx *de_ctx;
    Signature *s=NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;
    de_ctx->flags |= DE_QUIET;

    s = SigInit(de_ctx,"alert tcp any !any -> any any (msg:\"SigTest41-02 src ip is !any \"; classtype:misc-activity; sid:410002; rev:1;)");
    if (s != NULL) {
        SigFree(de_ctx, s);
        goto end;
    }

    result = 1;
end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}
/**
 * \test check that we don't allow invalid negation options
 */
static int SigParseTestNegation03 (void)
{
    int result = 0;
    DetectEngineCtx *de_ctx;
    Signature *s=NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;
    de_ctx->flags |= DE_QUIET;

    s = SigInit(de_ctx,"alert tcp any any -> any [80:!80] (msg:\"SigTest41-03 dst port [80:!80] \"; classtype:misc-activity; sid:410003; rev:1;)");
    if (s != NULL) {
        SigFree(de_ctx, s);
        goto end;
    }

    result = 1;
end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}
/**
 * \test check that we don't allow invalid negation options
 */
static int SigParseTestNegation04 (void)
{
    int result = 0;
    DetectEngineCtx *de_ctx;
    Signature *s=NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;
    de_ctx->flags |= DE_QUIET;

    s = SigInit(de_ctx,"alert tcp any any -> any [80,!80] (msg:\"SigTest41-03 dst port [80:!80] \"; classtype:misc-activity; sid:410003; rev:1;)");
    if (s != NULL) {
        SigFree(de_ctx, s);
        goto end;
    }

    result = 1;
end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}
/**
 * \test check that we don't allow invalid negation options
 */
static int SigParseTestNegation05 (void)
{
    int result = 0;
    DetectEngineCtx *de_ctx;
    Signature *s=NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;
    de_ctx->flags |= DE_QUIET;

    s = SigInit(de_ctx,"alert tcp any any -> [192.168.0.2,!192.168.0.2] any (msg:\"SigTest41-04 dst ip [192.168.0.2,!192.168.0.2] \"; classtype:misc-activity; sid:410004; rev:1;)");
    if (s != NULL) {
        SigFree(de_ctx, s);
        goto end;
    }

    result = 1;
end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}
/**
 * \test check that we don't allow invalid negation options
 */
static int SigParseTestNegation06 (void)
{
    int result = 0;
    DetectEngineCtx *de_ctx;
    Signature *s=NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;
    de_ctx->flags |= DE_QUIET;

    s = SigInit(de_ctx,"alert tcp any any -> any [100:1000,!1:20000] (msg:\"SigTest41-05 dst port [100:1000,!1:20000] \"; classtype:misc-activity; sid:410005; rev:1;)");
    if (s != NULL) {
        SigFree(de_ctx, s);
        goto end;
    }

    result = 1;
end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test check that we don't allow invalid negation options
 */
static int SigParseTestNegation07 (void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;
    Signature *s = DetectEngineAppendSig(
            de_ctx, "alert tcp any any -> [192.168.0.2,!192.168.0.0/24] any (sid:410006;)");
    FAIL_IF_NOT_NULL(s);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

/**
 * \test check valid negation bug 1079
 */
static int SigParseTestNegation08 (void)
{
    int result = 0;
    DetectEngineCtx *de_ctx;
    Signature *s=NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;
    de_ctx->flags |= DE_QUIET;

    s = SigInit(de_ctx,"alert tcp any any -> [192.168.0.0/16,!192.168.0.0/24] any (sid:410006; rev:1;)");
    if (s == NULL) {
        goto end;
    }

    result = 1;
end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test mpm
 */
static int SigParseTestMpm01 (void)
{
    int result = 0;
    Signature *sig = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    sig = SigInit(de_ctx, "alert tcp any any -> any any (msg:\"mpm test\"; content:\"abcd\"; sid:1;)");
    if (sig == NULL) {
        printf("sig failed to init: ");
        goto end;
    }

    if (sig->init_data->smlists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("sig doesn't have content list: ");
        goto end;
    }

    result = 1;
end:
    if (sig != NULL)
        SigFree(de_ctx, sig);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test mpm
 */
static int SigParseTestMpm02 (void)
{
    int result = 0;
    Signature *sig = NULL;

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    sig = SigInit(de_ctx, "alert tcp any any -> any any (msg:\"mpm test\"; content:\"abcd\"; content:\"abcdef\"; sid:1;)");
    if (sig == NULL) {
        printf("sig failed to init: ");
        goto end;
    }

    if (sig->init_data->smlists[DETECT_SM_LIST_PMATCH] == NULL) {
        printf("sig doesn't have content list: ");
        goto end;
    }

    result = 1;
end:
    if (sig != NULL)
        SigFree(de_ctx, sig);
    DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test test tls (app layer) rule
 */
static int SigParseTestAppLayerTLS01(void)
{
    int result = 0;
    DetectEngineCtx *de_ctx;
    Signature *s=NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;
    de_ctx->flags |= DE_QUIET;

    s = SigInit(de_ctx,"alert tls any any -> any any (msg:\"SigParseTestAppLayerTLS01 \"; sid:410006; rev:1;)");
    if (s == NULL) {
        printf("parsing sig failed: ");
        goto end;
    }

    if (s->alproto == 0) {
        printf("alproto not set: ");
        goto end;
    }

    result = 1;
end:
    if (s != NULL)
        SigFree(de_ctx, s);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);

    return result;
}

/**
 * \test test tls (app layer) rule
 */
static int SigParseTestAppLayerTLS02(void)
{
    int result = 0;
    DetectEngineCtx *de_ctx;
    Signature *s=NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;
    de_ctx->flags |= DE_QUIET;

    s = SigInit(de_ctx,"alert tls any any -> any any (msg:\"SigParseTestAppLayerTLS02 \"; tls.version:1.0; sid:410006; rev:1;)");
    if (s == NULL) {
        printf("parsing sig failed: ");
        goto end;
    }

    if (s->alproto == 0) {
        printf("alproto not set: ");
        goto end;
    }

    result = 1;
end:
    if (s != NULL)
        SigFree(de_ctx, s);
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

/**
 * \test test tls (app layer) rule
 */
static int SigParseTestAppLayerTLS03(void)
{
    int result = 0;
    DetectEngineCtx *de_ctx;
    Signature *s=NULL;

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;
    de_ctx->flags |= DE_QUIET;

    s = SigInit(de_ctx,"alert tls any any -> any any (msg:\"SigParseTestAppLayerTLS03 \"; tls.version:2.5; sid:410006; rev:1;)");
    if (s != NULL) {
        SigFree(de_ctx, s);
        goto end;
    }

    result = 1;
end:
    if (de_ctx != NULL)
        DetectEngineCtxFree(de_ctx);
    return result;
}

static int SigParseTestUnblanacedQuotes01(void)
{
    DetectEngineCtx *de_ctx;
    Signature *s;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    s = SigInit(de_ctx, "alert http any any -> any any (msg:\"SigParseTestUnblanacedQuotes01\"; pcre:\"/\\/[a-z]+\\.php\\?[a-z]+?=\\d{7}&[a-z]+?=\\d{7,8}$/U\" flowbits:set,et.exploitkitlanding; classtype:trojan-activity; sid:2017078; rev:5;)");
    FAIL_IF_NOT_NULL(s);

    PASS;
}

static int SigParseTestContentGtDsize01(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = SigInit(de_ctx,
            "alert http any any -> any any ("
            "dsize:21; content:\"0123456789001234567890|00 00|\"; "
            "sid:1; rev:1;)");
    FAIL_IF_NOT_NULL(s);

    PASS;
}

static int SigParseTestContentGtDsize02(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = SigInit(de_ctx,
            "alert http any any -> any any ("
            "dsize:21; content:\"0123456789|00 00|\"; offset:10; "
            "sid:1; rev:1;)");
    FAIL_IF_NOT_NULL(s);

    PASS;
}

static int CountSigsWithSid(const DetectEngineCtx *de_ctx, const uint32_t sid)
{
    int cnt = 0;
    for (Signature *s = de_ctx->sig_list; s != NULL; s = s->next) {
        if (sid == s->id)
            cnt++;
    }
    return cnt;
}

static int SigParseBidirWithSameSrcAndDest01(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    Signature *s = DetectEngineAppendSig(de_ctx, "alert tcp any any <> any any (sid:1;)");
    FAIL_IF_NULL(s);
    FAIL_IF_NOT(CountSigsWithSid(de_ctx, 1) == 1);
    FAIL_IF(s->init_data->init_flags & SIG_FLAG_INIT_BIDIREC);

    s = DetectEngineAppendSig(de_ctx, "alert tcp any [80, 81] <> any [81, 80] (sid:2;)");
    FAIL_IF_NULL(s);
    FAIL_IF_NOT(CountSigsWithSid(de_ctx, 2) == 1);
    FAIL_IF(s->init_data->init_flags & SIG_FLAG_INIT_BIDIREC);

    s = DetectEngineAppendSig(de_ctx,
            "alert tcp [1.2.3.4, 5.6.7.8] [80, 81] <> [5.6.7.8, 1.2.3.4] [81, 80] (sid:3;)");
    FAIL_IF_NULL(s);
    FAIL_IF_NOT(CountSigsWithSid(de_ctx, 3) == 1);
    FAIL_IF(s->init_data->init_flags & SIG_FLAG_INIT_BIDIREC);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int SigParseBidirWithSameSrcAndDest02(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    de_ctx->flags |= DE_QUIET;

    // Source is a subset of destination
    Signature *s = DetectEngineAppendSig(
            de_ctx, "alert tcp 1.2.3.4 any <> [1.2.3.4, 5.6.7.8, ::1] any (sid:1;)");
    FAIL_IF_NULL(s);
    FAIL_IF_NOT(CountSigsWithSid(de_ctx, 1) == 2);
    FAIL_IF_NOT(s->init_data->init_flags & SIG_FLAG_INIT_BIDIREC);

    // Source is a subset of destination
    s = DetectEngineAppendSig(
            de_ctx, "alert tcp [1.2.3.4, ::1] [80, 81, 82] <> [1.2.3.4, ::1] [80, 81] (sid:2;)");
    FAIL_IF_NULL(s);
    FAIL_IF_NOT(CountSigsWithSid(de_ctx, 2) == 2);
    FAIL_IF_NOT(s->init_data->init_flags & SIG_FLAG_INIT_BIDIREC);

    // Source intersects with destination
    s = DetectEngineAppendSig(de_ctx,
            "alert tcp [1.2.3.4, ::1, ABCD:AAAA::1] [80] <> [1.2.3.4, ::1] [80, 81] (sid:3;)");
    FAIL_IF_NULL(s);
    FAIL_IF_NOT(CountSigsWithSid(de_ctx, 3) == 2);
    FAIL_IF_NOT(s->init_data->init_flags & SIG_FLAG_INIT_BIDIREC);

    // mix in negation, these are the same
    s = DetectEngineAppendSig(
            de_ctx, "alert tcp [!1.2.3.4, 1.2.3.0/24] any <> [1.2.3.0/24, !1.2.3.4] any (sid:4;)");
    FAIL_IF_NULL(s);
    FAIL_IF_NOT(CountSigsWithSid(de_ctx, 4) == 1);
    FAIL_IF(s->init_data->init_flags & SIG_FLAG_INIT_BIDIREC);

    // mix in negation, these are not the same
    s = DetectEngineAppendSig(
            de_ctx, "alert tcp [1.2.3.4, 1.2.3.0/24] any <> [1.2.3.0/24, !1.2.3.4] any (sid:5;)");
    FAIL_IF_NULL(s);
    FAIL_IF_NOT(CountSigsWithSid(de_ctx, 5) == 2);
    FAIL_IF_NOT(s->init_data->init_flags & SIG_FLAG_INIT_BIDIREC);

    DetectEngineCtxFree(de_ctx);
    PASS;
}

#endif /* UNITTESTS */

#ifdef UNITTESTS
void DetectParseRegisterTests (void);
#include "tests/detect-parse.c"
#endif

void SigParseRegisterTests(void)
{
#ifdef UNITTESTS
    DetectParseRegisterTests();

    UtRegisterTest("SigParseTest01", SigParseTest01);
    UtRegisterTest("SigParseTest02", SigParseTest02);
    UtRegisterTest("SigParseTest03", SigParseTest03);
    UtRegisterTest("SigParseTest04", SigParseTest04);
    UtRegisterTest("SigParseTest05", SigParseTest05);
    UtRegisterTest("SigParseTest06", SigParseTest06);
    UtRegisterTest("SigParseTest07", SigParseTest07);
    UtRegisterTest("SigParseTest08", SigParseTest08);
    UtRegisterTest("SigParseTest09", SigParseTest09);
    UtRegisterTest("SigParseTest10", SigParseTest10);
    UtRegisterTest("SigParseTest11", SigParseTest11);
    UtRegisterTest("SigParseTest12", SigParseTest12);
    UtRegisterTest("SigParseTest13", SigParseTest13);
    UtRegisterTest("SigParseTest14", SigParseTest14);
    UtRegisterTest("SigParseTest15", SigParseTest15);
    UtRegisterTest("SigParseTest16", SigParseTest16);
    UtRegisterTest("SigParseTest17", SigParseTest17);
    UtRegisterTest("SigParseTest18", SigParseTest18);
    UtRegisterTest("SigParseTest19", SigParseTest19);
    UtRegisterTest("SigParseTest20", SigParseTest20);
    UtRegisterTest("SigParseTest21 -- address with space", SigParseTest21);
    UtRegisterTest("SigParseTest22 -- address with space", SigParseTest22);
    UtRegisterTest("SigParseTest23 -- carriage return", SigParseTest23);

    UtRegisterTest("SigParseBidirecTest06", SigParseBidirecTest06);
    UtRegisterTest("SigParseBidirecTest07", SigParseBidirecTest07);
    UtRegisterTest("SigParseBidirecTest08", SigParseBidirecTest08);
    UtRegisterTest("SigParseBidirecTest09", SigParseBidirecTest09);
    UtRegisterTest("SigParseBidirecTest10", SigParseBidirecTest10);
    UtRegisterTest("SigParseBidirecTest11", SigParseBidirecTest11);
    UtRegisterTest("SigParseBidirecTest12", SigParseBidirecTest12);
    UtRegisterTest("SigParseBidirecTest13", SigParseBidirecTest13);
    UtRegisterTest("SigParseBidirecTest14", SigParseBidirecTest14);
    UtRegisterTest("SigTestBidirec01", SigTestBidirec01);
    UtRegisterTest("SigTestBidirec02", SigTestBidirec02);
    UtRegisterTest("SigTestBidirec03", SigTestBidirec03);
    UtRegisterTest("SigTestBidirec04", SigTestBidirec04);
    UtRegisterTest("SigParseTestNegation01", SigParseTestNegation01);
    UtRegisterTest("SigParseTestNegation02", SigParseTestNegation02);
    UtRegisterTest("SigParseTestNegation03", SigParseTestNegation03);
    UtRegisterTest("SigParseTestNegation04", SigParseTestNegation04);
    UtRegisterTest("SigParseTestNegation05", SigParseTestNegation05);
    UtRegisterTest("SigParseTestNegation06", SigParseTestNegation06);
    UtRegisterTest("SigParseTestNegation07", SigParseTestNegation07);
    UtRegisterTest("SigParseTestNegation08", SigParseTestNegation08);
    UtRegisterTest("SigParseTestMpm01", SigParseTestMpm01);
    UtRegisterTest("SigParseTestMpm02", SigParseTestMpm02);
    UtRegisterTest("SigParseTestAppLayerTLS01", SigParseTestAppLayerTLS01);
    UtRegisterTest("SigParseTestAppLayerTLS02", SigParseTestAppLayerTLS02);
    UtRegisterTest("SigParseTestAppLayerTLS03", SigParseTestAppLayerTLS03);
    UtRegisterTest("SigParseTestUnblanacedQuotes01",
        SigParseTestUnblanacedQuotes01);

    UtRegisterTest("SigParseTestContentGtDsize01",
            SigParseTestContentGtDsize01);
    UtRegisterTest("SigParseTestContentGtDsize02",
            SigParseTestContentGtDsize02);

    UtRegisterTest("SigParseBidirWithSameSrcAndDest01",
            SigParseBidirWithSameSrcAndDest01);
    UtRegisterTest("SigParseBidirWithSameSrcAndDest02",
            SigParseBidirWithSameSrcAndDest02);
#endif /* UNITTESTS */
}

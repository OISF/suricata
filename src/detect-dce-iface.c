/* Copyright (C) 2007-2018 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 * Implements dce_iface keyword.
 */

#include "suricata-common.h"

#include "detect.h"
#include "detect-parse.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"
#include "detect-dce-iface.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "app-layer.h"
#include "app-layer-dcerpc.h"
#include "queue.h"
#include "stream-tcp-reassemble.h"

#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "stream-tcp.h"

#include "rust.h"
#include "rust-smb-detect-gen.h"

#define PARSE_REGEX "^\\s*([0-9a-zA-Z]{8}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{12})(?:\\s*,(<|>|=|!)([0-9]{1,5}))?(?:\\s*,(any_frag))?\\s*$"

static pcre *parse_regex = NULL;
static pcre_extra *parse_regex_study = NULL;

static int DetectDceIfaceMatchRust(ThreadVars *t,
        DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, void *state, void *txv,
        const Signature *s, const SigMatchCtx *m);
static int DetectDceIfaceSetup(DetectEngineCtx *, Signature *, const char *);
static void DetectDceIfaceFree(void *);
static void DetectDceIfaceRegisterTests(void);
static int g_dce_generic_list_id = 0;

static int InspectDceGeneric(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate,
        void *txv, uint64_t tx_id);

/**
 * \brief Registers the keyword handlers for the "dce_iface" keyword.
 */
void DetectDceIfaceRegister(void)
{
    sigmatch_table[DETECT_DCE_IFACE].name = "dcerpc.iface";
    sigmatch_table[DETECT_DCE_IFACE].alias = "dce_iface";
    sigmatch_table[DETECT_DCE_IFACE].AppLayerTxMatch = DetectDceIfaceMatchRust;
    sigmatch_table[DETECT_DCE_IFACE].Setup = DetectDceIfaceSetup;
    sigmatch_table[DETECT_DCE_IFACE].Free  = DetectDceIfaceFree;
    sigmatch_table[DETECT_DCE_IFACE].RegisterTests = DetectDceIfaceRegisterTests;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex, &parse_regex_study);

    g_dce_generic_list_id = DetectBufferTypeRegister("dce_generic");

    DetectAppLayerInspectEngineRegister("dce_generic",
            ALPROTO_DCERPC, SIG_FLAG_TOSERVER, 0, InspectDceGeneric);
    DetectAppLayerInspectEngineRegister("dce_generic",
            ALPROTO_SMB, SIG_FLAG_TOSERVER, 0, InspectDceGeneric);

    DetectAppLayerInspectEngineRegister("dce_generic",
            ALPROTO_DCERPC, SIG_FLAG_TOCLIENT, 0, InspectDceGeneric);
    DetectAppLayerInspectEngineRegister("dce_generic",
            ALPROTO_SMB, SIG_FLAG_TOCLIENT, 0, InspectDceGeneric);
}

static int InspectDceGeneric(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate,
        void *txv, uint64_t tx_id)
{
    return DetectEngineInspectGenericList(tv, de_ctx, det_ctx, s, smd,
                                          f, flags, alstate, txv, tx_id);
}


/**
 * \internal
 * \brief Parses the argument sent along with the "dce_iface" keyword.
 *
 * \param arg Pointer to the string containing the argument to be parsed.
 *
 * \retval did Pointer to a DetectDceIfaceData instance that holds the data
 *             from the parsed arg.
 */
static DetectDceIfaceData *DetectDceIfaceArgParse(const char *arg)
{
    DetectDceIfaceData *did = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];
    uint8_t hex_value;
    char copy_str[128] = "";
    int i = 0, j = 0;
    int len = 0;
    char temp_str[3] = "";
    int version;

    ret = pcre_exec(parse_regex, parse_regex_study, arg, strlen(arg), 0, 0, ov,
                    MAX_SUBSTRINGS);
    if (ret < 2) {
        SCLogError(SC_ERR_PCRE_MATCH, "pcre_exec parse error, ret %" PRId32 ", string %s", ret, arg);
        goto error;
    }

    if ( (did = SCMalloc(sizeof(DetectDceIfaceData))) == NULL)
        goto error;
    memset(did, 0, sizeof(DetectDceIfaceData));

    /* retrieve the iface uuid string.  iface uuid is a compulsion in the keyword */
    res = pcre_copy_substring(arg, ov, MAX_SUBSTRINGS, 1, copy_str, sizeof(copy_str));
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
        goto error;
    }

    /* parse the iface uuid string */
    len = strlen(copy_str);
    j = 0;
    temp_str[2] = '\0';
    for (i = 0; i < len; ) {
        if (copy_str[i] == '-') {
            i++;
            continue;
        }

        temp_str[0] = copy_str[i];
        temp_str[1] = copy_str[i + 1];

        hex_value = strtol(temp_str, NULL, 16);
        did->uuid[j] = hex_value;
        i += 2;
        j++;
    }

    /* if the regex has 3 or 5, any_frag option is present in the signature */
    if (ret == 3 || ret == 5)
        did->any_frag = 1;

    /* if the regex has 4 or 5, version/operator is present in the signature */
    if (ret == 4 || ret == 5) {
        /* first handle the version number, so that we can do some additional
         * validations of the version number, wrt. the operator */
        res = pcre_copy_substring(arg, ov, MAX_SUBSTRINGS, 3, copy_str, sizeof(copy_str));
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
            goto error;
        }

        version = atoi(copy_str);
        if (version > UINT16_MAX) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "DCE_IFACE interface version "
                       "invalid: %d\n", version);
            goto error;
        }
        did->version = version;

        /* now let us handle the operator supplied with the version number */
        res = pcre_copy_substring(arg, ov, MAX_SUBSTRINGS, 2, copy_str, sizeof(copy_str));
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
            goto error;
        }

        switch (copy_str[0]) {
            case '<':
                if (version == 0) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "DCE_IFACE interface "
                               "version invalid: %d.  Version can't be less"
                               "than 0, with \"<\" operator", version);
                    goto error;
                }

                did->op = DETECT_DCE_IFACE_OP_LT;
                break;
            case '>':
                if (version == UINT16_MAX) {
                    SCLogError(SC_ERR_INVALID_SIGNATURE, "DCE_IFACE interface "
                               "version invalid: %d.  Version can't be greater"
                               "than %d, with \">\" operator", version,
                               UINT16_MAX);
                    goto error;
                }

                did->op = DETECT_DCE_IFACE_OP_GT;
                break;
            case '=':
                did->op = DETECT_DCE_IFACE_OP_EQ;
                break;
            case '!':
                did->op = DETECT_DCE_IFACE_OP_NE;
                break;
        }
    }

    return did;

 error:
    if (did != NULL)
        SCFree(did);
    return NULL;
}

/**
 * \internal
 * \brief Internal function that compares the dce interface version for this
 *        flow, to the signature's interface version specified using the
 *        dce_iface keyword.
 *
 * \param version  The dce interface version for this flow.
 * \param dce_data Pointer to the Signature's dce_iface keyword
 *                 state(DetectDceIfaceData *).
 */
static inline int DetectDceIfaceMatchIfaceVersion(const uint16_t version,
                                                  const DetectDceIfaceData *dce_data)
{
    switch (dce_data->op) {
        case DETECT_DCE_IFACE_OP_LT:
            return (version < dce_data->version);
        case DETECT_DCE_IFACE_OP_GT:
            return (version > dce_data->version);
        case DETECT_DCE_IFACE_OP_EQ:
            return (version == dce_data->version);
        case DETECT_DCE_IFACE_OP_NE:
            return (version != dce_data->version);
        default:
            return 1;
    }
}

/**
 * \brief App layer match function for the "dce_iface" keyword.
 *
 * \param t       Pointer to the ThreadVars instance.
 * \param det_ctx Pointer to the DetectEngineThreadCtx.
 * \param f       Pointer to the flow.
 * \param flags   Pointer to the flags indicating the flow direction.
 * \param state   Pointer to the app layer state data.
 * \param s       Pointer to the Signature instance.
 * \param m       Pointer to the SigMatch.
 *
 * \retval 1 On Match.
 * \retval 0 On no match.
 */
static int DetectDceIfaceMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, void *state, void *txv,
        const Signature *s, const SigMatchCtx *m)
{
    SCEnter();

    int ret = 0;
    const DetectDceIfaceData *dce_data = (DetectDceIfaceData *)m;

    DCERPCUuidEntry *item = NULL;
    const DCERPCState *dcerpc_state = state;
    if (dcerpc_state == NULL) {
        SCLogDebug("No DCERPCState for the flow");
        SCReturnInt(0);
    }

    /* we still haven't seen a request */
    if (!dcerpc_state->dcerpc.dcerpcrequest.first_request_seen)
        goto end;

    if (!(dcerpc_state->dcerpc.dcerpchdr.type == REQUEST ||
          dcerpc_state->dcerpc.dcerpchdr.type == RESPONSE))
        goto end;

    TAILQ_FOREACH(item, &dcerpc_state->dcerpc.dcerpcbindbindack.accepted_uuid_list, next) {
        SCLogDebug("item %p", item);
        ret = 1;

        /* if any_frag is not enabled, we need to match only against the first
         * fragment */
        if (!dce_data->any_frag && !(item->flags & DCERPC_UUID_ENTRY_FLAG_FF))
            continue;

        /* if the uuid has been rejected(item->result == 1), we skip to the
         * next uuid */
        if (item->result != 0)
            continue;

        /* check the interface uuid */
        for (int i = 0; i < 16; i++) {
            if (dce_data->uuid[i] != item->uuid[i]) {
                ret = 0;
                break;
            }
        }
        ret &= (item->ctxid == dcerpc_state->dcerpc.dcerpcrequest.ctxid);
        if (ret == 0)
            continue;

        /* check the interface version */
        if (dce_data->op != DETECT_DCE_IFACE_OP_NONE &&
            !DetectDceIfaceMatchIfaceVersion(item->version, dce_data)) {
            ret &= 0;
        }

        /* we have a match.  Time to leave with a match */
        if (ret == 1)
            goto end;
    }

end:
    SCReturnInt(ret);
}

static int DetectDceIfaceMatchRust(ThreadVars *t,
        DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, void *state, void *txv,
        const Signature *s, const SigMatchCtx *m)
{
    SCEnter();

    if (f->alproto == ALPROTO_DCERPC) {
        return DetectDceIfaceMatch(t, det_ctx, f, flags,
                                   state, txv, s, m);
    }

    int ret = 0;
    DetectDceIfaceData *dce_data = (DetectDceIfaceData *)m;

    if (rs_smb_tx_get_dce_iface(f->alstate, txv, dce_data->uuid, 16, dce_data->op, dce_data->version) != 1) {
        SCLogDebug("rs_smb_tx_get_dce_iface: didn't match");
    } else {
        SCLogDebug("rs_smb_tx_get_dce_iface: matched!");
        ret = 1;
        // TODO validate frag
    }
    SCReturnInt(ret);
}

/**
 * \brief Creates a SigMatch for the "dce_iface" keyword being sent as argument,
 *        and appends it to the Signature(s).
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param s      Pointer to signature for the current Signature being parsed
 *               from the rules.
 * \param arg    Pointer to the string holding the keyword value.
 *
 * \retval 0 on success, -1 on failure.
 */

static int DetectDceIfaceSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    DetectDceIfaceData *did = DetectDceIfaceArgParse(arg);
    if (did == NULL) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "Error parsing dec_iface option in "
                   "signature");
        return -1;
    }

    SigMatch *sm = SigMatchAlloc();
    if (sm == NULL) {
        DetectDceIfaceFree(did);
        return -1;
    }

    sm->type = DETECT_DCE_IFACE;
    sm->ctx = (void *)did;

    SigMatchAppendSMToList(s, sm, g_dce_generic_list_id);
    return 0;
}

static void DetectDceIfaceFree(void *ptr)
{
    SCFree(ptr);

    return;
}

/************************************Unittests*********************************/

#ifdef UNITTESTS

static int DetectDceIfaceTestParse01(void)
{
    SCEnter();

    Signature *s = SigAlloc();
    if (s == NULL)
        return 0;

    int result = 0;
    DetectDceIfaceData *did = NULL;
    uint8_t test_uuid[] = {0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34,
                           0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
    SigMatch *temp = NULL;
    int i = 0;

    result = (DetectDceIfaceSetup(NULL, s, "12345678-1234-1234-1234-123456789ABC") == 0);

    if (s->sm_lists[g_dce_generic_list_id] == NULL) {
        SCReturnInt(0);
    }

    temp = s->sm_lists[g_dce_generic_list_id];
    did = (DetectDceIfaceData *)temp->ctx;
    if (did == NULL) {
        SCReturnInt(0);
    }

    result &= 1;
    for (i = 0; i < 16; i++) {
        if (did->uuid[i] != test_uuid[i]) {
            result = 0;
            break;
        }
    }

    result &= (did->version == 0);
    result &= (did->op == 0);
    result &= (did->any_frag == 0);

    SigFree(s);
    SCReturnInt(result);
}

static int DetectDceIfaceTestParse02(void)
{
    SCEnter();

    Signature *s = SigAlloc();
    if (s == NULL)
        return 0;

    int result = 0;
    DetectDceIfaceData *did = NULL;
    uint8_t test_uuid[] = {0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34,
                           0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
    SigMatch *temp = NULL;
    int i = 0;

    result = (DetectDceIfaceSetup(NULL, s, "12345678-1234-1234-1234-123456789ABC,>1") == 0);

    if (s->sm_lists[g_dce_generic_list_id] == NULL) {
        SCReturnInt(0);
    }

    temp = s->sm_lists[g_dce_generic_list_id];
    did = (DetectDceIfaceData *)temp->ctx;
    if (did == NULL) {
        SCReturnInt(0);
    }

    result &= 1;
    for (i = 0; i < 16; i++) {
        if (did->uuid[i] != test_uuid[i]) {
            result = 0;
            break;
        }
    }

    result &= (did->version == 1);
    result &= (did->op == DETECT_DCE_IFACE_OP_GT);
    result &= (did->any_frag == 0);

    SigFree(s);
    SCReturnInt(result);
}

static int DetectDceIfaceTestParse03(void)
{
    SCEnter();

    Signature *s = SigAlloc();
    if (s == NULL)
        return 0;

    int result = 0;
    DetectDceIfaceData *did = NULL;
    uint8_t test_uuid[] = {0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34,
                           0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
    SigMatch *temp = NULL;
    int i = 0;

    result = (DetectDceIfaceSetup(NULL, s, "12345678-1234-1234-1234-123456789ABC,<10") == 0);

    if (s->sm_lists[g_dce_generic_list_id] == NULL) {
        SCReturnInt(0);
    }

    temp = s->sm_lists[g_dce_generic_list_id];
    did = (DetectDceIfaceData *)temp->ctx;
    result &= 1;
    for (i = 0; i < 16; i++) {
        if (did->uuid[i] != test_uuid[i]) {
            result = 0;
            break;
        }
    }

    result &= (did->version == 10);
    result &= (did->op == DETECT_DCE_IFACE_OP_LT);
    result &= (did->any_frag == 0);

    SigFree(s);
    SCReturnInt(result);
}

static int DetectDceIfaceTestParse04(void)
{
    SCEnter();

    Signature *s = SigAlloc();
    if (s == NULL)
        return 0;

    int result = 0;
    DetectDceIfaceData *did = NULL;
    uint8_t test_uuid[] = {0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34,
                           0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
    SigMatch *temp = NULL;
    int i = 0;

    result = (DetectDceIfaceSetup(NULL, s, "12345678-1234-1234-1234-123456789ABC,!10") == 0);

    if (s->sm_lists[g_dce_generic_list_id] == NULL) {
        SCReturnInt(0);
    }

    temp = s->sm_lists[g_dce_generic_list_id];
    did = (DetectDceIfaceData *)temp->ctx;
    if (did == NULL) {
        SCReturnInt(0);
    }

    result &= 1;
    for (i = 0; i < 16; i++) {
        if (did->uuid[i] != test_uuid[i]) {
            result = 0;
            break;
        }
    }

    result &= (did->version == 10);
    result &= (did->op == DETECT_DCE_IFACE_OP_NE);
    result &= (did->any_frag == 0);

    SigFree(s);
    SCReturnInt(result);
}

static int DetectDceIfaceTestParse05(void)
{
    SCEnter();

    Signature *s = SigAlloc();
    int result = 0;
    DetectDceIfaceData *did = NULL;
    uint8_t test_uuid[] = {0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34,
                           0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
    SigMatch *temp = NULL;
    int i = 0;

    result = (DetectDceIfaceSetup(NULL, s, "12345678-1234-1234-1234-123456789ABC,=10") == 0);

    if (s->sm_lists[g_dce_generic_list_id] == NULL) {
        SCReturnInt(0);
    }

    temp = s->sm_lists[g_dce_generic_list_id];
    did = (DetectDceIfaceData *)temp->ctx;
    if (did == NULL) {
        SCReturnInt(0);
    }

    result &= 1;
    for (i = 0; i < 16; i++) {
        if (did->uuid[i] != test_uuid[i]) {
            result = 0;
            break;
        }
    }

    result &= (did->version == 10);
    result &= (did->op == DETECT_DCE_IFACE_OP_EQ);
    result &= (did->any_frag == 0);

    SigFree(s);
    SCReturnInt(result);
}

static int DetectDceIfaceTestParse06(void)
{
    SCEnter();

    Signature *s = SigAlloc();
    if (s == NULL)
        return 0;

    int result = 0;
    DetectDceIfaceData *did = NULL;
    uint8_t test_uuid[] = {0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34,
                           0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
    SigMatch *temp = NULL;
    int i = 0;

    result = (DetectDceIfaceSetup(NULL, s, "12345678-1234-1234-1234-123456789ABC,any_frag") == 0);

    if (s->sm_lists[g_dce_generic_list_id] == NULL) {
        SCReturnInt(0);
    }

    temp = s->sm_lists[g_dce_generic_list_id];
    did = (DetectDceIfaceData *)temp->ctx;
    if (did == NULL) {
        SCReturnInt(0);
    }

    result &= 1;
    for (i = 0; i < 16; i++) {
        if (did->uuid[i] != test_uuid[i]) {
            result = 0;
            break;
        }
    }

    result &= (did->version == 0);
    result &= (did->op == 0);
    result &= (did->any_frag == 1);

    SigFree(s);
    SCReturnInt(result);
}

static int DetectDceIfaceTestParse07(void)
{
    SCEnter();

    Signature *s = SigAlloc();
    if (s == NULL)
        return 0;

    int result = 0;
    DetectDceIfaceData *did = NULL;
    uint8_t test_uuid[] = {0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34,
                           0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
    SigMatch *temp = NULL;
    int i = 0;

    result = (DetectDceIfaceSetup(NULL, s, "12345678-1234-1234-1234-123456789ABC,>1,any_frag") == 0);

    if (s->sm_lists[g_dce_generic_list_id] == NULL) {
        SCReturnInt(0);
    }

    temp = s->sm_lists[g_dce_generic_list_id];
    did = (DetectDceIfaceData *)temp->ctx;
    if (did == NULL) {
        SCReturnInt(0);
    }

    result &= 1;
    for (i = 0; i < 16; i++) {
        if (did->uuid[i] != test_uuid[i]) {
            result = 0;
            break;
        }
    }

    result &= (did->version == 1);
    result &= (did->op == DETECT_DCE_IFACE_OP_GT);
    result &= (did->any_frag == 1);

    SigFree(s);
    SCReturnInt(result);
}

static int DetectDceIfaceTestParse08(void)
{
    Signature *s = SigAlloc();
    if (s == NULL)
        return 0;

    int result = 0;
    DetectDceIfaceData *did = NULL;
    uint8_t test_uuid[] = {0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34,
                           0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
    SigMatch *temp = NULL;
    int i = 0;

    result = (DetectDceIfaceSetup(NULL, s, "12345678-1234-1234-1234-123456789ABC,<1,any_frag") == 0);

    if (s->sm_lists[g_dce_generic_list_id] == NULL) {
        SCReturnInt(0);
    }

    temp = s->sm_lists[g_dce_generic_list_id];
    did = (DetectDceIfaceData *)temp->ctx;
    if (did == NULL) {
        SCReturnInt(0);
    }

    result &= 1;
    for (i = 0; i < 16; i++) {
        if (did->uuid[i] != test_uuid[i]) {
            result = 0;
            break;
        }
    }

    result &= (did->version == 1);
    result &= (did->op == DETECT_DCE_IFACE_OP_LT);
    result &= (did->any_frag == 1);

    SigFree(s);
    SCReturnInt(result);
}

static int DetectDceIfaceTestParse09(void)
{
    SCEnter();

    Signature *s = SigAlloc();
    if (s == NULL)
        return 0;

    int result = 0;
    DetectDceIfaceData *did = NULL;
    uint8_t test_uuid[] = {0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34,
                           0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
    SigMatch *temp = NULL;
    int i = 0;

    result = (DetectDceIfaceSetup(NULL, s, "12345678-1234-1234-1234-123456789ABC,=1,any_frag") == 0);

    temp = s->sm_lists[g_dce_generic_list_id];
    did = (DetectDceIfaceData *)temp->ctx;
    if (did == NULL) {
        SCReturnInt(0);
    }

    result &= 1;
    for (i = 0; i < 16; i++) {
        if (did->uuid[i] != test_uuid[i]) {
            result = 0;
            break;
        }
    }

    result &= (did->version == 1);
    result &= (did->op == DETECT_DCE_IFACE_OP_EQ);
    result &= (did->any_frag == 1);

    SigFree(s);
    SCReturnInt(result);
}

static int DetectDceIfaceTestParse10(void)
{
    SCEnter();

    Signature *s = SigAlloc();
    if (s == NULL)
        return 0;

    int result = 0;
    DetectDceIfaceData *did = NULL;
    uint8_t test_uuid[] = {0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34,
                           0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
    SigMatch *temp = NULL;
    int i = 0;

    result = (DetectDceIfaceSetup(NULL, s, "12345678-1234-1234-1234-123456789ABC,!1,any_frag") == 0);

    if (s->sm_lists[g_dce_generic_list_id] == NULL) {
        SCReturnInt(0);
    }

    temp = s->sm_lists[g_dce_generic_list_id];
    did = (DetectDceIfaceData *)temp->ctx;
    if (did == NULL) {
        SCReturnInt(0);
    }

    result &= 1;
    for (i = 0; i < 16; i++) {
        if (did->uuid[i] != test_uuid[i]) {
            result = 0;
            break;
        }
    }

    result &= (did->version == 1);
    result &= (did->op == DETECT_DCE_IFACE_OP_NE);
    result &= (did->any_frag == 1);

    SigFree(s);
    SCReturnInt(result);
}

static int DetectDceIfaceTestParse11(void)
{
    SCEnter();

    Signature *s = SigAlloc();
    if (s == NULL)
        return 0;

    int result = 1;

    result &= (DetectDceIfaceSetup(NULL, s, "12345678-1234-1234-1234-123456789ABC,>1,ay_frag") == -1);
    result &= (DetectDceIfaceSetup(NULL, s, "12345678-1234-1234-1234-12345679ABC,>1,any_frag") == -1);
    result &= (DetectDceIfaceSetup(NULL, s, "12345678-1234-1234-134-123456789ABC,>1,any_frag") == -1);
    result &= (DetectDceIfaceSetup(NULL, s, "12345678-123-124-1234-123456789ABC,>1,any_frag") == -1);
    result &= (DetectDceIfaceSetup(NULL, s, "1234568-1234-1234-1234-123456789ABC,>1,any_frag") == -1);
    result &= (DetectDceIfaceSetup(NULL, s, "12345678-1234-1234-1234-123456789ABC,>65536,any_frag") == -1);
    result &= (DetectDceIfaceSetup(NULL, s, "12345678-1234-1234-1234-123456789ABC,>=1,any_frag") == -1);
    result &= (DetectDceIfaceSetup(NULL, s, "12345678-1234-1234-1234-123456789ABC,<0,any_frag") == -1);
    result &= (DetectDceIfaceSetup(NULL, s, "12345678-1234-1234-1234-123456789ABC,>65535,any_frag") == -1);

    SigFree(s);
    return result;
}

/**
 * \test Test a valid dce_iface entry for a bind and bind_ack
 */
static int DetectDceIfaceTestParse12(void)
{
    Signature *s = NULL;
    ThreadVars th_v;
    Packet *p = NULL;
    Flow f;
    TcpSession ssn;
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    DCERPCState *dcerpc_state = NULL;
    int r = 0;

    uint8_t dcerpc_bind[] = {
        0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0xb8, 0x10, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x6a, 0x28, 0x19, 0x39, 0x0c, 0xb1, 0xd0, 0x11,
        0x9b, 0xa8, 0x00, 0xc0, 0x4f, 0xd9, 0x2e, 0xf5,
        0x00, 0x00, 0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a,
        0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00,
        0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00,
    };

    uint8_t dcerpc_bindack[] = {
        0x05, 0x00, 0x0c, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x44, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0xb8, 0x10, 0xb8, 0x10, 0x26, 0x3d, 0x00, 0x00,
        0x0c, 0x00, 0x5c, 0x50, 0x49, 0x50, 0x45, 0x5c,
        0x6c, 0x73, 0x61, 0x73, 0x73, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
        0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
        0x02, 0x00, 0x00, 0x00
    };

    uint8_t dcerpc_request[] = {
        0x05, 0x00, 0x00, 0x01, 0x10, 0x00, 0x00, 0x00,
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00,
        0xad, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    uint32_t dcerpc_bind_len = sizeof(dcerpc_bind);
    uint32_t dcerpc_bindack_len = sizeof(dcerpc_bindack);
    uint32_t dcerpc_request_len = sizeof(dcerpc_request);

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_DCERPC;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    FAIL_IF(de_ctx == NULL);
    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx,"alert tcp any any -> any any "
                                   "(msg:\"DCERPC\"; "
                                   "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5,=0,any_frag; "
                                   "sid:1;)");
    FAIL_IF(s == NULL);

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCLogDebug("handling to_server chunk");

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DCERPC,
                            STREAM_TOSERVER | STREAM_START, dcerpc_bind,
                            dcerpc_bind_len);
    FAIL_IF(r != 0);

    dcerpc_state = f.alstate;
    FAIL_IF(dcerpc_state == NULL);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));

    SCLogDebug("handling to_client chunk");

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DCERPC,
                            STREAM_TOCLIENT, dcerpc_bindack,
                            dcerpc_bindack_len);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    FAIL_IF(PacketAlertCheck(p, 1));

    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DCERPC,
                            STREAM_TOCLIENT, dcerpc_request,
                            dcerpc_request_len);
    FAIL_IF(r != 0);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    FAIL_IF(!PacketAlertCheck(p, 1));
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    PASS;
}

/* Disabled because of bug_753.  Would be enabled, once we rewrite
 * dce parser */
#if 0

/**
 * \test Test a valid dce_iface entry with a bind, bind_ack and 3 request/responses.
 */
static int DetectDceIfaceTestParse13(void)
{
    int result = 0;
    Signature *s = NULL;
    ThreadVars th_v;
    Packet *p = NULL;
    Flow f;
    TcpSession ssn;
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    DCERPCState *dcerpc_state = NULL;
    int r = 0;

    uint8_t dcerpc_bind[] = {
        0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0xb8, 0x10, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x01, 0xd0, 0x8c, 0x33, 0x44, 0x22, 0xf1, 0x31,
        0xaa, 0xaa, 0x90, 0x00, 0x38, 0x00, 0x10, 0x03,
        0x01, 0x00, 0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a,
        0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00,
        0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00,
    };

    uint8_t dcerpc_bindack[] = {
        0x05, 0x00, 0x0c, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x44, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0xb8, 0x10, 0xb8, 0x10, 0x65, 0x8e, 0x00, 0x00,
        0x0d, 0x00, 0x5c, 0x50, 0x49, 0x50, 0x45, 0x5c,
        0x77, 0x69, 0x6e, 0x72, 0x65, 0x67, 0x00, 0x6d,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
        0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
        0x02, 0x00, 0x00, 0x00,
    };

    uint8_t dcerpc_request1[] = {
        0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x24, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
        0x2c, 0xfd, 0xb5, 0x00, 0x40, 0xaa, 0x01, 0x00,
        0x00, 0x00, 0x00, 0x02,
    };

    uint8_t dcerpc_response1[] = {
        0x05, 0x00, 0x02, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x30, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xf6, 0x72, 0x28, 0x9c,
        0xf0, 0x57, 0xd8, 0x11, 0xb0, 0x05, 0x00, 0x0c,
        0x29, 0x87, 0xea, 0xe9, 0x00, 0x00, 0x00, 0x00,
    };

    uint8_t dcerpc_request2[] = {
        0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
        0xa4, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x8c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xf6, 0x72, 0x28, 0x9c,
        0xf0, 0x57, 0xd8, 0x11, 0xb0, 0x05, 0x00, 0x0c,
        0x29, 0x87, 0xea, 0xe9, 0x5c, 0x00, 0x5c, 0x00,
        0xa8, 0xb9, 0x14, 0x00, 0x2e, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x2e, 0x00, 0x00, 0x00,
        0x53, 0x00, 0x4f, 0x00, 0x46, 0x00, 0x54, 0x00,
        0x57, 0x00, 0x41, 0x00, 0x52, 0x00, 0x45, 0x00,
        0x5c, 0x00, 0x4d, 0x00, 0x69, 0x00, 0x63, 0x00,
        0x72, 0x00, 0x6f, 0x00, 0x73, 0x00, 0x6f, 0x00,
        0x66, 0x00, 0x74, 0x00, 0x5c, 0x00, 0x57, 0x00,
        0x69, 0x00, 0x6e, 0x00, 0x64, 0x00, 0x6f, 0x00,
        0x77, 0x00, 0x73, 0x00, 0x5c, 0x00, 0x43, 0x00,
        0x75, 0x00, 0x72, 0x00, 0x72, 0x00, 0x65, 0x00,
        0x6e, 0x00, 0x74, 0x00, 0x56, 0x00, 0x65, 0x00,
        0x72, 0x00, 0x73, 0x00, 0x69, 0x00, 0x6f, 0x00,
        0x6e, 0x00, 0x5c, 0x00, 0x52, 0x00, 0x75, 0x00,
        0x6e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x00, 0x00, 0x00,
    };

    uint8_t dcerpc_response2[] = {
        0x05, 0x00, 0x02, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x30, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xf7, 0x72, 0x28, 0x9c,
        0xf0, 0x57, 0xd8, 0x11, 0xb0, 0x05, 0x00, 0x0c,
        0x29, 0x87, 0xea, 0xe9, 0x00, 0x00, 0x00, 0x00,
    };

    uint8_t dcerpc_request3[] = {
        0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x70, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x58, 0x00, 0x00, 0x00, 0x00, 0x00, 0x16, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xf7, 0x72, 0x28, 0x9c,
        0xf0, 0x57, 0xd8, 0x11, 0xb0, 0x05, 0x00, 0x0c,
        0x29, 0x87, 0xea, 0xe9, 0x0c, 0x00, 0x0c, 0x00,
        0x98, 0xda, 0x14, 0x00, 0x06, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00,
        0x4f, 0x00, 0x73, 0x00, 0x61, 0x00, 0x33, 0x00,
        0x32, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x18, 0x00, 0x00, 0x00, 0x4e, 0x00, 0x54, 0x00,
        0x4f, 0x00, 0x53, 0x00, 0x41, 0x00, 0x33, 0x00,
        0x32, 0x00, 0x2e, 0x00, 0x45, 0x00, 0x58, 0x00,
        0x45, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00,
    };

    uint8_t dcerpc_response3[] = {
        0x05, 0x00, 0x02, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x1c, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };

    uint32_t dcerpc_bind_len = sizeof(dcerpc_bind);
    uint32_t dcerpc_bindack_len = sizeof(dcerpc_bindack);

    uint32_t dcerpc_request1_len = sizeof(dcerpc_request1);
    uint32_t dcerpc_response1_len = sizeof(dcerpc_response1);

    uint32_t dcerpc_request2_len = sizeof(dcerpc_request2);
    uint32_t dcerpc_response2_len = sizeof(dcerpc_response2);

    uint32_t dcerpc_request3_len = sizeof(dcerpc_request3);
    uint32_t dcerpc_response3_len = sizeof(dcerpc_response3);

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_DCERPC;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx,"alert tcp any any -> any any "
            "(msg:\"DCERPC\"; dce_iface:338cd001-2244-31f1-aaaa-900038001003,=1,any_frag; sid:1;)");
    if (s == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCLogDebug("chunk 1, bind");

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DCERPC, STREAM_TOSERVER | STREAM_START,
                            dcerpc_bind, dcerpc_bind_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    dcerpc_state = f.alstate;
    if (dcerpc_state == NULL) {
        SCLogDebug("no dcerpc state: ");
        goto end;
    }

    p->flowflags &=~ FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_TOSERVER;
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 didn't match after bind request: ");
        goto end;
    }

    SCLogDebug("chunk 2, bind_ack");

    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DCERPC, STREAM_TOCLIENT, dcerpc_bindack,
                            dcerpc_bindack_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    p->flowflags &=~ FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 matched again after bind ack: ");
        goto end;
    }

    SCLogDebug("chunk 3, request 1");

    /* request1 */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DCERPC, STREAM_TOSERVER, dcerpc_request1,
                            dcerpc_request1_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    p->flowflags &=~ FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_TOSERVER;
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        printf("sig 1 didn't match after request1: ");
        goto end;
    }

    SCLogDebug("sending response1");

    /* response1 */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DCERPC, STREAM_TOCLIENT, dcerpc_response1,
                            dcerpc_response1_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    p->flowflags &=~ FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 matched after response1, but shouldn't: ");
        goto end;
    }

    SCLogDebug("sending request2");

    /* request2 */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DCERPC, STREAM_TOSERVER, dcerpc_request2,
                            dcerpc_request2_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    p->flowflags &=~ FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_TOSERVER;
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        printf("sig 1 didn't match after request2: ");
        goto end;
    }

    /* response2 */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DCERPC, STREAM_TOCLIENT, dcerpc_response2,
                            dcerpc_response2_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    p->flowflags &=~ FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 matched after response2, but shouldn't have: ");
        goto end;
    }

    /* request3 */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DCERPC, STREAM_TOSERVER, dcerpc_request3,
                            dcerpc_request3_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    p->flowflags &=~ FLOW_PKT_TOCLIENT;
    p->flowflags |= FLOW_PKT_TOSERVER;
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!(PacketAlertCheck(p, 1))) {
        printf("sig 1 didn't match after request3: ");
        goto end;
    }

    /* response3 */
    r = AppLayerParserParse(alp_tctx, &f, ALPROTO_DCERPC, STREAM_TOCLIENT | STREAM_EOF,
                            dcerpc_response3, dcerpc_response3_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    p->flowflags &=~ FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_TOCLIENT;
    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 matched after response3, but shouldn't have: ");
        goto end;
    }

    result = 1;

 end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    UTHFreePackets(&p, 1);
    return result;
}

#endif

/**
 * \test Test a valid dce_iface entry for a bind and bind_ack
 */
static int DetectDceIfaceTestParse14(void)
{
    int result = 0;
    Signature *s = NULL;
    ThreadVars th_v;
    Packet *p = NULL;
    Flow f;
    TcpSession ssn;
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    DCERPCState *dcerpc_state = NULL;
    int r = 0;

    uint8_t dcerpc_bind[] = {
        0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0xb8, 0x10, 0xb8, 0x10, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x6a, 0x28, 0x19, 0x39, 0x0c, 0xb1, 0xd0, 0x11,
        0x9b, 0xa8, 0x00, 0xc0, 0x4f, 0xd9, 0x2e, 0xf5,
        0x00, 0x00, 0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a,
        0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00,
        0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00,
    };

    uint8_t dcerpc_bindack[] = {
        0x05, 0x00, 0x0c, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x44, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0xb8, 0x10, 0xb8, 0x10, 0x26, 0x3d, 0x00, 0x00,
        0x0c, 0x00, 0x5c, 0x50, 0x49, 0x50, 0x45, 0x5c,
        0x6c, 0x73, 0x61, 0x73, 0x73, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
        0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
        0x02, 0x00, 0x00, 0x00
    };

    uint8_t dcerpc_request[] = {
        0x05, 0x00, 0x00, 0x01, 0x10, 0x00, 0x00, 0x00,
        0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x09, 0x00,
        0xad, 0x0d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    uint32_t dcerpc_bind_len = sizeof(dcerpc_bind);
    uint32_t dcerpc_bindack_len = sizeof(dcerpc_bindack);
    uint32_t dcerpc_request_len = sizeof(dcerpc_request);

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    p->flow = &f;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    f.alproto = ALPROTO_DCERPC;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                                   "(msg:\"DCERPC\"; "
                                   "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5,=0; "
                                   "sid:1;)");
    if (s == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DCERPC,
                            STREAM_TOSERVER | STREAM_START, dcerpc_bind,
                            dcerpc_bind_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    dcerpc_state = f.alstate;
    if (dcerpc_state == NULL) {
        SCLogDebug("no dcerpc state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1))
        goto end;

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DCERPC,
                            STREAM_TOCLIENT, dcerpc_bindack,
                            dcerpc_bindack_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 matched but shouldn't have: ");
        goto end;
    }

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DCERPC,
                            STREAM_TOCLIENT, dcerpc_request,
                            dcerpc_request_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 matched but shouldn't have: ");
        goto end;
    }

    result = 1;

 end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Test a valid dce_iface entry for a bind and bind_ack
 */
static int DetectDceIfaceTestParse15(void)
{
    int result = 0;
    Signature *s = NULL;
    ThreadVars th_v;
    Packet *p = NULL;
    Flow f;
    TcpSession ssn;
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    DCERPCState *dcerpc_state = NULL;
    int r = 0;

    uint8_t dcerpc_bind[] = {
        0x05, 0x00, 0x0b, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0xd0, 0x16, 0xd0, 0x16, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x40, 0xfd, 0x2c, 0x34, 0x6c, 0x3c, 0xce, 0x11,
        0xa8, 0x93, 0x08, 0x00, 0x2b, 0x2e, 0x9c, 0x6d,
        0x00, 0x00, 0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a,
        0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00,
        0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00
    };
    uint32_t dcerpc_bind_len = sizeof(dcerpc_bind);

    uint8_t dcerpc_bindack[] = {
        0x05, 0x00, 0x0c, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x44, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0xb8, 0x10, 0xb8, 0x10, 0x7d, 0xd8, 0x00, 0x00,
        0x0d, 0x00, 0x5c, 0x70, 0x69, 0x70, 0x65, 0x5c,
        0x6c, 0x6c, 0x73, 0x72, 0x70, 0x63, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
        0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
        0x02, 0x00, 0x00, 0x00
    };
    uint32_t dcerpc_bindack_len = sizeof(dcerpc_bindack);

    uint8_t dcerpc_alter_context[] = {
        0x05, 0x00, 0x0e, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x48, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0xd0, 0x16, 0xd0, 0x16, 0x00, 0x00, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00,
        0xd0, 0x4c, 0x67, 0x57, 0x00, 0x52, 0xce, 0x11,
        0xa8, 0x97, 0x08, 0x00, 0x2b, 0x2e, 0x9c, 0x6d,
        0x01, 0x00, 0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a,
        0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00,
        0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00
    };
    uint32_t dcerpc_alter_context_len = sizeof(dcerpc_alter_context);

    uint8_t dcerpc_alter_context_resp[] = {
        0x05, 0x00, 0x0f, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x38, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0xb8, 0x10, 0xb8, 0x10, 0x7d, 0xd8, 0x00, 0x00,
        0x00, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x04, 0x5d, 0x88, 0x8a,
        0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00,
        0x2b, 0x10, 0x48, 0x60, 0x02, 0x00, 0x00, 0x00
    };
    uint32_t dcerpc_alter_context_resp_len = sizeof(dcerpc_alter_context_resp);

    uint8_t dcerpc_request1[] = {
        0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x20, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x20, 0x03, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0xdd, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    uint32_t dcerpc_request1_len = sizeof(dcerpc_request1);

    uint8_t dcerpc_response1[] = {
        0x05, 0x00, 0x02, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x30, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x18, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xf5, 0x66, 0xbf, 0x54,
        0xc4, 0xdb, 0xdb, 0x4f, 0xa0, 0x01, 0x6d, 0xf4,
        0xf6, 0xa8, 0x44, 0xb3, 0x00, 0x00, 0x00, 0x00
    };
    uint32_t dcerpc_response1_len = sizeof(dcerpc_response1);

    uint8_t dcerpc_request2[] = {
        0x05, 0x00, 0x00, 0x03, 0x10, 0x00, 0x00, 0x00,
        0x20, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
        0xc6, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x07, 0x9f, 0x13, 0xd9,
    };
    uint32_t dcerpc_request2_len = sizeof(dcerpc_request2);

    AppLayerParserThreadCtx *alp_tctx = AppLayerParserThreadCtxAlloc();

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
    f.proto = IPPROTO_TCP;
    p->flow = &f;
    p->flags |= PKT_HAS_FLOW|PKT_STREAM_EST;
    p->flowflags |= FLOW_PKT_TOSERVER;
    p->flowflags |= FLOW_PKT_ESTABLISHED;
    f.alproto = ALPROTO_DCERPC;

    StreamTcpInitConfig(TRUE);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                              "(msg:\"DCERPC\"; "
                              "dce_iface:57674cd0-5200-11ce-a897-08002b2e9c6d; "
                              "sid:1;)");
    if (s == NULL)
        goto end;

    s = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any "
                              "(msg:\"DCERPC\"; "
                              "dce_iface:342cfd40-3c6c-11ce-a893-08002b2e9c6d; "
                              "sid:2;)");
    if (s == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DCERPC,
                            STREAM_TOSERVER | STREAM_START, dcerpc_bind,
                            dcerpc_bind_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    dcerpc_state = f.alstate;
    if (dcerpc_state == NULL) {
        SCLogDebug("no dcerpc state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1))
        goto end;
    if (PacketAlertCheck(p, 2))
        goto end;

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DCERPC,
                            STREAM_TOCLIENT, dcerpc_bindack,
                            dcerpc_bindack_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 matched but shouldn't have: ");
        goto end;
    }
    if (PacketAlertCheck(p, 2)) {
        printf("sig 1 matched but shouldn't have: ");
        goto end;
    }

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DCERPC,
                            STREAM_TOSERVER, dcerpc_alter_context,
                            dcerpc_alter_context_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 matched but shouldn't have: ");
        goto end;
    }
    if (PacketAlertCheck(p, 2)) {
        printf("sig 1 matched but shouldn't have: ");
        goto end;
    }

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DCERPC,
                            STREAM_TOCLIENT, dcerpc_alter_context_resp,
                            dcerpc_alter_context_resp_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 matched but shouldn't have: ");
        goto end;
    }
    if (PacketAlertCheck(p, 2)) {
        printf("sig 1 matched but shouldn't have: ");
        goto end;
    }

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DCERPC,
                            STREAM_TOSERVER, dcerpc_request1,
                            dcerpc_request1_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 matched but shouldn't have: ");
        goto end;
    }
    if (PacketAlertCheck(p, 2)) {
        printf("sig 1 matched but shouldn't have: ");
        goto end;
    }

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DCERPC,
                            STREAM_TOCLIENT, dcerpc_response1,
                            dcerpc_response1_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 matched but shouldn't have: ");
        goto end;
    }
    if (PacketAlertCheck(p, 2)) {
        printf("sig 1 matched but shouldn't have: ");
        goto end;
    }

    FLOWLOCK_WRLOCK(&f);
    r = AppLayerParserParse(NULL, alp_tctx, &f, ALPROTO_DCERPC,
                            STREAM_TOSERVER, dcerpc_request2,
                            dcerpc_request2_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        FLOWLOCK_UNLOCK(&f);
        goto end;
    }
    FLOWLOCK_UNLOCK(&f);

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 matched but shouldn't have: ");
        goto end;
    }
    if (!PacketAlertCheck(p, 2)) {
        printf("sig 1 matched but shouldn't have: ");
        goto end;
    }

    result = 1;

 end:
    if (alp_tctx != NULL)
        AppLayerParserThreadCtxFree(alp_tctx);
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

#endif

static void DetectDceIfaceRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectDceIfaceTestParse01", DetectDceIfaceTestParse01);
    UtRegisterTest("DetectDceIfaceTestParse02", DetectDceIfaceTestParse02);
    UtRegisterTest("DetectDceIfaceTestParse03", DetectDceIfaceTestParse03);
    UtRegisterTest("DetectDceIfaceTestParse04", DetectDceIfaceTestParse04);
    UtRegisterTest("DetectDceIfaceTestParse05", DetectDceIfaceTestParse05);
    UtRegisterTest("DetectDceIfaceTestParse06", DetectDceIfaceTestParse06);
    UtRegisterTest("DetectDceIfaceTestParse07", DetectDceIfaceTestParse07);
    UtRegisterTest("DetectDceIfaceTestParse08", DetectDceIfaceTestParse08);
    UtRegisterTest("DetectDceIfaceTestParse09", DetectDceIfaceTestParse09);
    UtRegisterTest("DetectDceIfaceTestParse10", DetectDceIfaceTestParse10);
    UtRegisterTest("DetectDceIfaceTestParse11", DetectDceIfaceTestParse11);
    UtRegisterTest("DetectDceIfaceTestParse12", DetectDceIfaceTestParse12);
    /* Disabled because of bug_753.  Would be enabled, once we rewrite
     * dce parser */
#if 0
    UtRegisterTest("DetectDceIfaceTestParse13", DetectDceIfaceTestParse13, 1);
#endif
    UtRegisterTest("DetectDceIfaceTestParse14", DetectDceIfaceTestParse14);
    UtRegisterTest("DetectDceIfaceTestParse15", DetectDceIfaceTestParse15);
#endif
}

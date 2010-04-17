/* Copyright (c) 2009 Open Information Security Foundation. */

/** \file
 *  \author Anoop Saldanha <poonaatsoc@gmail.com>
 */

#include "suricata-common.h"

#include "detect.h"
#include "detect-parse.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-dce-iface.h"

#include "flow.h"
#include "flow-var.h"

#include "app-layer.h"
#include "app-layer-dcerpc.h"
#include "queue.h"
#include "stream-tcp-reassemble.h"

#include "util-debug.h"
#include "util-unittest.h"
#include "stream-tcp.h"

#define DETECT_DCE_IFACE_PCRE_PARSE_ARGS "^\\s*([0-9a-zA-Z]{8}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{12})(?:\\s*,(<|>|=|!)([0-9]{1,5}))?(?:\\s*,(any_frag))?\\s*$"

static pcre *parse_regex = NULL;
static pcre_extra *parse_regex_study = NULL;

int DetectDceIfaceMatch(ThreadVars *, DetectEngineThreadCtx *, Flow *, uint8_t,
                        void *, Signature *, SigMatch *);
static int DetectDceIfaceSetup(DetectEngineCtx *, Signature *, char *);
void DetectDceIfaceFree(void *);

/**
 * \brief Registers the keyword handlers for the "dce_iface" keyword.
 */
void DetectDceIfaceRegister(void)
{
    const char *eb;
    int eo;
    int opts = 0;

    sigmatch_table[DETECT_DCE_IFACE].name = "dce_iface";
    sigmatch_table[DETECT_DCE_IFACE].alproto = ALPROTO_DCERPC;
    sigmatch_table[DETECT_DCE_IFACE].Match = NULL;
    sigmatch_table[DETECT_DCE_IFACE].AppLayerMatch = DetectDceIfaceMatch;
    sigmatch_table[DETECT_DCE_IFACE].Setup = DetectDceIfaceSetup;
    sigmatch_table[DETECT_DCE_IFACE].Free  = DetectDceIfaceFree;
    sigmatch_table[DETECT_DCE_IFACE].RegisterTests = DetectDceIfaceRegisterTests;

    sigmatch_table[DETECT_DCE_IFACE].flags |= SIGMATCH_PAYLOAD;

    parse_regex = pcre_compile(DETECT_DCE_IFACE_PCRE_PARSE_ARGS, opts, &eb,
                               &eo, NULL);
    if (parse_regex == NULL) {
        SCLogDebug("pcre compile of \"%s\" failed at offset %" PRId32 ": %s",
                   DETECT_DCE_IFACE_PCRE_PARSE_ARGS, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if (eb != NULL) {
        SCLogDebug("pcre study failed: %s", eb);
        goto error;
    }

    return;

 error:
    /* we need to handle error?! */
    return;
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
static inline DetectDceIfaceData *DetectDceIfaceArgParse(const char *arg)
{
    DetectDceIfaceData *did = NULL;
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];
    uint8_t hex_value;
    const char *pcre_sub_str = NULL;
    int i = 0, j = 0;
    int len = 0;
    char temp_str[3];
    int version;

    ret = pcre_exec(parse_regex, parse_regex_study, arg, strlen(arg), 0, 0, ov,
                    MAX_SUBSTRINGS);
    if (ret < 2) {
        SCLogError(SC_ERR_PCRE_MATCH, "pcre_exec parse error, ret %" PRId32 ", string %s", ret, arg);
        goto error;
    }

    if ( (did = SCMalloc(sizeof(DetectDceIfaceData))) == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        goto error;
    }
    memset(did, 0, sizeof(DetectDceIfaceData));

    /* retrieve the iface uuid string.  iface uuid is a compulsion in the keyword */
    res = pcre_get_substring(arg, ov, MAX_SUBSTRINGS, 1, &pcre_sub_str);
    if (res < 0) {
        SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
        goto error;
    }

    /* parse the iface uuid string */
    len = strlen(pcre_sub_str);
    j = 0;
    temp_str[2] = '\0';
    for (i = 0; i < len; ) {
        if (pcre_sub_str[i] == '-') {
            i++;
            continue;
        }

        temp_str[0] = pcre_sub_str[i];
        temp_str[1] = pcre_sub_str[i + 1];

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
        res = pcre_get_substring(arg, ov, MAX_SUBSTRINGS, 3, &pcre_sub_str);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
            goto error;
        }

        version = atoi(pcre_sub_str);
        if (version > UINT16_MAX) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "DCE_IFACE interface version "
                       "invalid: %d\n", version);
            goto error;
        }
        did->version = version;

        /* free the substring */
        pcre_free_substring(pcre_sub_str);

        /* now let us handle the operator supplied with the version number */
        res = pcre_get_substring(arg, ov, MAX_SUBSTRINGS, 2, &pcre_sub_str);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
            goto error;
        }

        switch (pcre_sub_str[0]) {
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

        /* free the substring */
        pcre_free_substring(pcre_sub_str);
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
static inline int DetectDceIfaceMatchIfaceVersion(uint16_t version,
                                                  DetectDceIfaceData *dce_data)
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
int DetectDceIfaceMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx, Flow *f,
                        uint8_t flags, void *state, Signature *s, SigMatch *m)
{
    int ret = 1;
    DCERPCUuidEntry *item = NULL;
    int i = 0;
    DetectDceIfaceData *dce_data = (DetectDceIfaceData *)m->ctx;
    DCERPCState *dcerpc_state = (DCERPCState *)state;
    if (dcerpc_state == NULL) {
        SCLogDebug("No DCERPCState for the flow");
        return 0;
    }

    SCMutexLock(&f->m);

    /* if any_frag is not enabled, we need to match only against the first
     * fragment */
    if (!dce_data->any_frag &&
        !(dcerpc_state->dcerpc.dcerpchdr.pfc_flags & PFC_FIRST_FRAG)) {
        /* any_frag has not been set, and apparently it's not the first fragment */
        ret = 0;
        goto end;
    }

    TAILQ_FOREACH(item, &dcerpc_state->dcerpc.dcerpcbindbindack.uuid_list, next) {
        ret = 1;

        /* if the uuid has been rejected(item->result == 1), we skip to the
         * next uuid */
        if (item->result == 1)
            continue;

        /* check the interface uuid */
        for (i = 0; i < 16; i++) {
            if (dce_data->uuid[i] != item->uuid[i]) {
                ret = 0;
                break;
            }
        }

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
    SCMutexUnlock(&f->m);
    return ret;
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

static int DetectDceIfaceSetup(DetectEngineCtx *de_ctx, Signature *s, char *arg)
{
    DetectDceIfaceData *did = NULL;
    SigMatch *sm = NULL;

    did = DetectDceIfaceArgParse(arg);
    if (did == NULL) {
        SCLogError(SC_ERR_INVALID_SIGNATURE, "Error parsing dec_iface option in "
                   "signature");
        goto error;
    }

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_DCE_IFACE;
    sm->ctx = (void *)did;

    SigMatchAppendAppLayer(s, sm);

    if (s->alproto != ALPROTO_UNKNOWN && s->alproto != ALPROTO_DCERPC) {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "rule contains conflicting keywords.");
        goto error;
    }

    s->alproto = ALPROTO_DCERPC;
    return 0;

 error:
    DetectDceIfaceFree(did);
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

void DetectDceIfaceFree(void *ptr)
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
    int result = 0;
    DetectDceIfaceData *did = NULL;
    uint8_t test_uuid[] = {0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34,
                           0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
    SigMatch *temp = NULL;
    int i = 0;

    result = (DetectDceIfaceSetup(NULL, s, "12345678-1234-1234-1234-123456789ABC") == 0);

    if (s->match == NULL) {
        SCReturnInt(0);
    }

    temp = s->match;
    did = temp->ctx;
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
    int result = 0;
    DetectDceIfaceData *did = NULL;
    uint8_t test_uuid[] = {0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34,
                           0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
    SigMatch *temp = NULL;
    int i = 0;

    result = (DetectDceIfaceSetup(NULL, s, "12345678-1234-1234-1234-123456789ABC,>1") == 0);

    if (s->match == NULL) {
        SCReturnInt(0);
    }

    temp = s->match;
    did = temp->ctx;
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
    int result = 0;
    DetectDceIfaceData *did = NULL;
    uint8_t test_uuid[] = {0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34,
                           0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
    SigMatch *temp = NULL;
    int i = 0;

    result = (DetectDceIfaceSetup(NULL, s, "12345678-1234-1234-1234-123456789ABC,<10") == 0);

    if (s->match == NULL) {
        SCReturnInt(0);
    }

    temp = s->match;
    did = temp->ctx;
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
    int result = 0;
    DetectDceIfaceData *did = NULL;
    uint8_t test_uuid[] = {0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34,
                           0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
    SigMatch *temp = NULL;
    int i = 0;

    result = (DetectDceIfaceSetup(NULL, s, "12345678-1234-1234-1234-123456789ABC,!10") == 0);

    if (s->match == NULL) {
        SCReturnInt(0);
    }

    temp = s->match;
    did = temp->ctx;
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

    if (s->match == NULL) {
        SCReturnInt(0);
    }

    temp = s->match;
    did = temp->ctx;
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
    int result = 0;
    DetectDceIfaceData *did = NULL;
    uint8_t test_uuid[] = {0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34,
                           0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
    SigMatch *temp = NULL;
    int i = 0;

    result = (DetectDceIfaceSetup(NULL, s, "12345678-1234-1234-1234-123456789ABC,any_frag") == 0);

    if (s->match == NULL) {
        SCReturnInt(0);
    }

    temp = s->match;
    did = temp->ctx;
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
    int result = 0;
    DetectDceIfaceData *did = NULL;
    uint8_t test_uuid[] = {0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34,
                           0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
    SigMatch *temp = NULL;
    int i = 0;

    result = (DetectDceIfaceSetup(NULL, s, "12345678-1234-1234-1234-123456789ABC,>1,any_frag") == 0);

    if (s->match == NULL) {
        SCReturnInt(0);
    }

    temp = s->match;
    did = temp->ctx;
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
    int result = 0;
    DetectDceIfaceData *did = NULL;
    uint8_t test_uuid[] = {0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34,
                           0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
    SigMatch *temp = NULL;
    int i = 0;

    result = (DetectDceIfaceSetup(NULL, s, "12345678-1234-1234-1234-123456789ABC,<1,any_frag") == 0);

    if (s->match == NULL) {
        SCReturnInt(0);
    }

    temp = s->match;
    did = temp->ctx;
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
    int result = 0;
    DetectDceIfaceData *did = NULL;
    uint8_t test_uuid[] = {0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34,
                           0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
    SigMatch *temp = NULL;
    int i = 0;

    result = (DetectDceIfaceSetup(NULL, s, "12345678-1234-1234-1234-123456789ABC,=1,any_frag") == 0);

    temp = s->match;
    did = temp->ctx;
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
    int result = 0;
    DetectDceIfaceData *did = NULL;
    uint8_t test_uuid[] = {0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34,
                           0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
    SigMatch *temp = NULL;
    int i = 0;

    result = (DetectDceIfaceSetup(NULL, s, "12345678-1234-1234-1234-123456789ABC,!1,any_frag") == 0);

    if (s->match == NULL) {
        SCReturnInt(0);
    }

    temp = s->match;
    did = temp->ctx;
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
    int result = 0;
    Signature *s = NULL;
    ThreadVars th_v;
    Packet p;
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

    uint32_t dcerpc_bind_len = sizeof(dcerpc_bind);
    uint32_t dcerpc_bindack_len = sizeof(dcerpc_bindack);

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = NULL;
    p.payload_len = 0;
    p.proto = IPPROTO_TCP;

    f.protoctx = (void *)&ssn;
    p.flow = &f;
    p.flowflags |= FLOW_PKT_TOSERVER;
    ssn.alproto = ALPROTO_DCERPC;

    StreamTcpInitConfig(TRUE);
    StreamL7DataPtrInit(&ssn);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,
                                   "alert tcp any any -> any any "
                                   "(msg:\"DCERPC\"; "
                                   "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5,=0,any_frag; "
                                   "sid:1;)");
    if (s == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    r = AppLayerParse(&f, ALPROTO_DCERPC, STREAM_TOSERVER | STREAM_START,
                      dcerpc_bind, dcerpc_bind_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    dcerpc_state = ssn.aldata[AlpGetStateIdx(ALPROTO_DCERPC)];
    if (dcerpc_state == NULL) {
        SCLogDebug("no dcerpc state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);

    if (!PacketAlertCheck(&p, 1))
        goto end;

    r = AppLayerParse(&f, ALPROTO_DCERPC, STREAM_TOCLIENT, dcerpc_bindack,
                      dcerpc_bindack_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);

    if (!PacketAlertCheck(&p, 1))
        goto end;

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamL7DataPtrFree(&ssn);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/**
 * \test Test a valid dce_iface entry with a bind, bind_ack and 3 request/responses.
 */
static int DetectDceIfaceTestParse13(void)
{
    int result = 0;
    Signature *s = NULL;
    ThreadVars th_v;
    Packet p;
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

    uint32_t dcerpc_request1_len = sizeof(dcerpc_request1_len);
    uint32_t dcerpc_response1_len = sizeof(dcerpc_response1_len);

    uint32_t dcerpc_request2_len = sizeof(dcerpc_request2_len);
    uint32_t dcerpc_response2_len = sizeof(dcerpc_response2_len);

    uint32_t dcerpc_request3_len = sizeof(dcerpc_request3_len);
    uint32_t dcerpc_response3_len = sizeof(dcerpc_response3_len);

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = NULL;
    p.payload_len = 0;
    p.proto = IPPROTO_TCP;

    f.protoctx = (void *)&ssn;
    p.flow = &f;
    p.flowflags |= FLOW_PKT_TOSERVER;
    ssn.alproto = ALPROTO_DCERPC;

    StreamTcpInitConfig(TRUE);
    StreamL7DataPtrInit(&ssn);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,
                                   "alert tcp any any -> any any "
                                   "(msg:\"DCERPC\"; "
                                   "dce_iface:338cd001-2244-31f1-aaaa-900038001003,=1,any_frag; "
                                   "sid:1;)");
    if (s == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    r = AppLayerParse(&f, ALPROTO_DCERPC, STREAM_TOSERVER | STREAM_START,
                      dcerpc_bind, dcerpc_bind_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    dcerpc_state = ssn.aldata[AlpGetStateIdx(ALPROTO_DCERPC)];
    if (dcerpc_state == NULL) {
        SCLogDebug("no dcerpc state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);

    if (!PacketAlertCheck(&p, 1))
        goto end;

    r = AppLayerParse(&f, ALPROTO_DCERPC, STREAM_TOCLIENT, dcerpc_bindack,
                      dcerpc_bindack_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);

    if (!PacketAlertCheck(&p, 1))
        goto end;

    /* request1 */
    r = AppLayerParse(&f, ALPROTO_DCERPC, STREAM_TOSERVER, dcerpc_request1,
                      dcerpc_request1_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);

    if (!PacketAlertCheck(&p, 1))
        goto end;

    /* response1 */
    r = AppLayerParse(&f, ALPROTO_DCERPC, STREAM_TOCLIENT, dcerpc_response1,
                      dcerpc_response1_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);

    if (!PacketAlertCheck(&p, 1))
        goto end;

    /* request2 */
    r = AppLayerParse(&f, ALPROTO_DCERPC, STREAM_TOSERVER, dcerpc_request2,
                      dcerpc_request2_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);

    if (!PacketAlertCheck(&p, 1))
        goto end;

    /* response2 */
    r = AppLayerParse(&f, ALPROTO_DCERPC, STREAM_TOCLIENT, dcerpc_response2,
                      dcerpc_response2_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);

    if (!PacketAlertCheck(&p, 1))
        goto end;

    /* request3 */
    r = AppLayerParse(&f, ALPROTO_DCERPC, STREAM_TOSERVER, dcerpc_request3,
                      dcerpc_request3_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);

    if (!PacketAlertCheck(&p, 1))
        goto end;

    /* response3 */
    r = AppLayerParse(&f, ALPROTO_DCERPC, STREAM_TOCLIENT | STREAM_EOF,
                      dcerpc_response3, dcerpc_response3_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);

    if (!PacketAlertCheck(&p, 1))
        goto end;

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamL7DataPtrFree(&ssn);
    StreamTcpFreeConfig(TRUE);
    return result;
}

/**
 * \test Test a valid dce_iface entry for a bind and bind_ack
 */
static int DetectDceIfaceTestParse14(void)
{
    int result = 0;
    Signature *s = NULL;
    ThreadVars th_v;
    Packet p;
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

    uint32_t dcerpc_bind_len = sizeof(dcerpc_bind);
    uint32_t dcerpc_bindack_len = sizeof(dcerpc_bindack);

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p.src.family = AF_INET;
    p.dst.family = AF_INET;
    p.payload = NULL;
    p.payload_len = 0;
    p.proto = IPPROTO_TCP;

    f.protoctx = (void *)&ssn;
    p.flow = &f;
    p.flowflags |= FLOW_PKT_TOSERVER;
    ssn.alproto = ALPROTO_DCERPC;

    StreamTcpInitConfig(TRUE);
    StreamL7DataPtrInit(&ssn);

    de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    s = de_ctx->sig_list = SigInit(de_ctx,
                                   "alert tcp any any -> any any "
                                   "(msg:\"DCERPC\"; "
                                   "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5,=0; "
                                   "sid:1;)");
    if (s == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    r = AppLayerParse(&f, ALPROTO_DCERPC, STREAM_TOSERVER | STREAM_START,
                      dcerpc_bind, dcerpc_bind_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    dcerpc_state = ssn.aldata[AlpGetStateIdx(ALPROTO_DCERPC)];
    if (dcerpc_state == NULL) {
        SCLogDebug("no dcerpc state: ");
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);

    if (!PacketAlertCheck(&p, 1))
        goto end;

    r = AppLayerParse(&f, ALPROTO_DCERPC, STREAM_TOCLIENT, dcerpc_bindack,
                      dcerpc_bindack_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, &p);

    if (!PacketAlertCheck(&p, 1))
        goto end;

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamL7DataPtrFree(&ssn);
    StreamTcpFreeConfig(TRUE);
    return result;
}

#endif

void DetectDceIfaceRegisterTests(void)
{

#ifdef UNITTESTS
    UtRegisterTest("DetectDceIfaceTestParse01", DetectDceIfaceTestParse01, 1);
    UtRegisterTest("DetectDceIfaceTestParse02", DetectDceIfaceTestParse02, 1);
    UtRegisterTest("DetectDceIfaceTestParse03", DetectDceIfaceTestParse03, 1);
    UtRegisterTest("DetectDceIfaceTestParse04", DetectDceIfaceTestParse04, 1);
    UtRegisterTest("DetectDceIfaceTestParse05", DetectDceIfaceTestParse05, 1);
    UtRegisterTest("DetectDceIfaceTestParse06", DetectDceIfaceTestParse06, 1);
    UtRegisterTest("DetectDceIfaceTestParse07", DetectDceIfaceTestParse07, 1);
    UtRegisterTest("DetectDceIfaceTestParse08", DetectDceIfaceTestParse08, 1);
    UtRegisterTest("DetectDceIfaceTestParse09", DetectDceIfaceTestParse09, 1);
    UtRegisterTest("DetectDceIfaceTestParse10", DetectDceIfaceTestParse10, 1);
    UtRegisterTest("DetectDceIfaceTestParse11", DetectDceIfaceTestParse11, 1);
    UtRegisterTest("DetectDceIfaceTestParse12", DetectDceIfaceTestParse12, 1);
    UtRegisterTest("DetectDceIfaceTestParse13", DetectDceIfaceTestParse13, 1);
    UtRegisterTest("DetectDceIfaceTestParse14", DetectDceIfaceTestParse14, 1);
#endif

    return;
}

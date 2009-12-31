/** Copyright (c) 2009 Open Information Security Foundation.
 *  \author Anoop Saldanha <poonaatsoc@gmail.com>
 */

#include "suricata-common.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-dce-iface.h"
#include "app-layer-dcerpc.h"
#include "queue.h"

#include "util-debug.h"
#include "util-unittest.h"

#define DETECT_DCE_IFACE_PCRE_PARSE_ARGS "^\\s*([0-9a-zA-Z]{8}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{12})(?:\\s*,(<|>|=|!)([0-9]{1,5}))?(?:\\s*,(any_frag))?\\s*$"

static pcre *parse_regex = NULL;
static pcre_extra *parse_regex_study = NULL;

int DetectDceIfaceMatch(ThreadVars *, DetectEngineThreadCtx *, Flow *, uint8_t,
                        void *, Signature *, SigMatch *);
int DetectDceIfaceSetup(DetectEngineCtx *, Signature *s, SigMatch *m, char *arg);
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
    sigmatch_table[DETECT_DCE_IFACE].Match = NULL;
    sigmatch_table[DETECT_DCE_IFACE].AppLayerMatch = DetectDceIfaceMatch;
    sigmatch_table[DETECT_DCE_IFACE].Setup = DetectDceIfaceSetup;
    sigmatch_table[DETECT_DCE_IFACE].Free  = DetectDceIfaceFree;
    sigmatch_table[DETECT_DCE_IFACE].RegisterTests = DetectDceIfaceRegisterTests;

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
        SCLogDebug("pcre_exec parse error, ret %" PRId32 ", string %s", ret, arg);
        goto error;
    }

    if ( (did = malloc(sizeof(DetectDceIfaceData))) == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        goto error;
    }
    memset(did, 0, sizeof(DetectDceIfaceData));

    res = pcre_get_substring(arg, ov, MAX_SUBSTRINGS, 1, &pcre_sub_str);
    if (res < 0) {
        SCLogError(SC_PCRE_GET_SUBSTRING_FAILED, "pcre_get_substring failed");
        goto error;
    }

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

    if (ret == 3 || ret == 5)
        did->any_frag = 1;

    if (ret == 4 || ret == 5) {
        res = pcre_get_substring(arg, ov, MAX_SUBSTRINGS, 2, &pcre_sub_str);
        if (res < 0) {
            SCLogError(SC_PCRE_GET_SUBSTRING_FAILED, "pcre_get_substring failed");
            goto error;
        }

        switch (pcre_sub_str[0]) {
            case '<':
                did->op = DETECT_DCE_IFACE_OP_LT;
                break;
            case '>':
                did->op = DETECT_DCE_IFACE_OP_GT;
                break;
            case '=':
                did->op = DETECT_DCE_IFACE_OP_EQ;
                break;
            case '!':
                did->op = DETECT_DCE_IFACE_OP_NE;
                break;
        }

        res = pcre_get_substring(arg, ov, MAX_SUBSTRINGS, 3, &pcre_sub_str);
        if (res < 0) {
            SCLogError(SC_PCRE_GET_SUBSTRING_FAILED, "pcre_get_substring failed");
            goto error;
        }

        version = atoi(pcre_sub_str);
        if (version > 65535) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "DCE_IFACE interface version "
                       "invalid: %d\n", version);
            goto error;
        }
        did->version = version;
    }

    return did;

 error:
    if (did != NULL)
        free(did);
    return NULL;
}

int DetectDceIfaceMatch(ThreadVars *t, DetectEngineThreadCtx *det_ctx, Flow *f,
                        uint8_t flags, void *state, Signature *s, SigMatch *m)
{
    int ret = 1;
    struct entry *item = NULL;
    DetectDceIfaceData *dce_data = (DetectDceIfaceData *)m->ctx;
    DCERPCState *dcerpc_state = (DCERPCState *)state;
    if (dcerpc_state == NULL) {
        SCLogDebug("No DCERPCState for the flow");
        return 0;
    }

    SCMutexLock(&f->m);
    int i = 0;

    TAILQ_FOREACH(item, &dcerpc_state->head, entries) {
        for (i = 0; i < 16; i++) {
            if (dce_data->uuid[i] != item->uuid[i]) {
                ret = 0;
                break;
            }
        }
    }

    return 1;
}

/**
 * \brief Creates a SigMatch for the "dce_iface" keyword being sent as argument,
 *        and appends it to the Signature(s).
 *
 * \param de_ctx Pointer to the detection engine context.
 * \param s      Pointer to signature for the current Signature being parsed
 *               from the rules.
 * \param m      Pointer to the head of the SigMatchs for the current rule
 *               being parsed.
 * \param arg    Pointer to the string holding the keyword value.
 *
 * \retval 0 on success, -1 on failure.
 */

int DetectDceIfaceSetup(DetectEngineCtx *de_ctx, Signature *s, SigMatch *m,
                        char *arg)
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

    SigMatchAppend(s, m, sm);

    return 0;

 error:
    DetectDceIfaceFree(did);
    if (sm != NULL)
        free(sm);
    return -1;
}

void DetectDceIfaceFree(void *ptr)
{
    free(ptr);

    return;
}

/************************************Unittests*********************************/

#ifdef UNITTESTS

static int DetectDceIfaceTestParse01(void)
{
    Signature *s = SigAlloc();
    int result = 0;
    DetectDceIfaceData *did = NULL;
    uint8_t test_uuid[] = {0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34,
                           0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
    SigMatch *temp = NULL;
    int i = 0;

    result = (DetectDceIfaceSetup(NULL, s, NULL, "12345678-1234-1234-1234-123456789ABC") == 0);

    if (s->match != NULL) {
        temp = s->match;
        did = temp->ctx;
        result &= 1;
        for (i = 0; i < 16; i++) {
            if (did->uuid[i] != test_uuid[i]) {
                result = 0;
                break;
            }
        }
    }

    result &= (did->version == 0);
    result &= (did->op == 0);
    result &= (did->any_frag == 0);

    SigFree(s);
    return result;
}

static int DetectDceIfaceTestParse02(void)
{
    Signature *s = SigAlloc();
    int result = 0;
    DetectDceIfaceData *did = NULL;
    uint8_t test_uuid[] = {0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34,
                           0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
    SigMatch *temp = NULL;
    int i = 0;

    result = (DetectDceIfaceSetup(NULL, s, NULL, "12345678-1234-1234-1234-123456789ABC,>1") == 0);

    if (s->match != NULL) {
        temp = s->match;
        did = temp->ctx;
        result &= 1;
        for (i = 0; i < 16; i++) {
            if (did->uuid[i] != test_uuid[i]) {
                result = 0;
                break;
            }
        }
    }

    result &= (did->version == 1);
    result &= (did->op == DETECT_DCE_IFACE_OP_GT);
    result &= (did->any_frag == 0);

    SigFree(s);
    return result;
}

static int DetectDceIfaceTestParse03(void)
{
    Signature *s = SigAlloc();
    int result = 0;
    DetectDceIfaceData *did = NULL;
    uint8_t test_uuid[] = {0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34,
                           0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
    SigMatch *temp = NULL;
    int i = 0;

    result = (DetectDceIfaceSetup(NULL, s, NULL, "12345678-1234-1234-1234-123456789ABC,<10") == 0);

    if (s->match != NULL) {
        temp = s->match;
        did = temp->ctx;
        result &= 1;
        for (i = 0; i < 16; i++) {
            if (did->uuid[i] != test_uuid[i]) {
                result = 0;
                break;
            }
        }
    }

    result &= (did->version == 10);
    result &= (did->op == DETECT_DCE_IFACE_OP_LT);
    result &= (did->any_frag == 0);

    SigFree(s);
    return result;
}

static int DetectDceIfaceTestParse04(void)
{
    Signature *s = SigAlloc();
    int result = 0;
    DetectDceIfaceData *did = NULL;
    uint8_t test_uuid[] = {0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34,
                           0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
    SigMatch *temp = NULL;
    int i = 0;

    result = (DetectDceIfaceSetup(NULL, s, NULL, "12345678-1234-1234-1234-123456789ABC,!10") == 0);

    if (s->match != NULL) {
        temp = s->match;
        did = temp->ctx;
        result &= 1;
        for (i = 0; i < 16; i++) {
            if (did->uuid[i] != test_uuid[i]) {
                result = 0;
                break;
            }
        }
    }

    result &= (did->version == 10);
    result &= (did->op == DETECT_DCE_IFACE_OP_NE);
    result &= (did->any_frag == 0);

    SigFree(s);
    return result;
}

static int DetectDceIfaceTestParse05(void)
{
    Signature *s = SigAlloc();
    int result = 0;
    DetectDceIfaceData *did = NULL;
    uint8_t test_uuid[] = {0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34,
                           0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
    SigMatch *temp = NULL;
    int i = 0;

    result = (DetectDceIfaceSetup(NULL, s, NULL, "12345678-1234-1234-1234-123456789ABC,=10") == 0);

    if (s->match != NULL) {
        temp = s->match;
        did = temp->ctx;
        result &= 1;
        for (i = 0; i < 16; i++) {
            if (did->uuid[i] != test_uuid[i]) {
                result = 0;
                break;
            }
        }
    }

    result &= (did->version == 10);
    result &= (did->op == DETECT_DCE_IFACE_OP_EQ);
    result &= (did->any_frag == 0);

    SigFree(s);
    return result;
}

static int DetectDceIfaceTestParse06(void)
{
    Signature *s = SigAlloc();
    int result = 0;
    DetectDceIfaceData *did = NULL;
    uint8_t test_uuid[] = {0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34,
                           0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
    SigMatch *temp = NULL;
    int i = 0;

    result = (DetectDceIfaceSetup(NULL, s, NULL, "12345678-1234-1234-1234-123456789ABC,any_frag") == 0);

    if (s->match != NULL) {
        temp = s->match;
        did = temp->ctx;
        result &= 1;
        for (i = 0; i < 16; i++) {
            if (did->uuid[i] != test_uuid[i]) {
                result = 0;
                break;
            }
        }
    }

    result &= (did->version == 0);
    result &= (did->op == 0);
    result &= (did->any_frag == 1);

    SigFree(s);
    return result;
}

static int DetectDceIfaceTestParse07(void)
{
    Signature *s = SigAlloc();
    int result = 0;
    DetectDceIfaceData *did = NULL;
    uint8_t test_uuid[] = {0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34,
                           0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
    SigMatch *temp = NULL;
    int i = 0;

    result = (DetectDceIfaceSetup(NULL, s, NULL, "12345678-1234-1234-1234-123456789ABC,>1,any_frag") == 0);

    if (s->match != NULL) {
        temp = s->match;
        did = temp->ctx;
        result &= 1;
        for (i = 0; i < 16; i++) {
            if (did->uuid[i] != test_uuid[i]) {
                result = 0;
                break;
            }
        }
    }

    result &= (did->version == 1);
    result &= (did->op == DETECT_DCE_IFACE_OP_GT);
    result &= (did->any_frag == 1);

    SigFree(s);
    return result;
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

    result = (DetectDceIfaceSetup(NULL, s, NULL, "12345678-1234-1234-1234-123456789ABC,<1,any_frag") == 0);

    if (s->match != NULL) {
        temp = s->match;
        did = temp->ctx;
        result &= 1;
        for (i = 0; i < 16; i++) {
            if (did->uuid[i] != test_uuid[i]) {
                result = 0;
                break;
            }
        }
    }

    result &= (did->version == 1);
    result &= (did->op == DETECT_DCE_IFACE_OP_LT);
    result &= (did->any_frag == 1);

    SigFree(s);
    return result;
}

static int DetectDceIfaceTestParse09(void)
{
    Signature *s = SigAlloc();
    int result = 0;
    DetectDceIfaceData *did = NULL;
    uint8_t test_uuid[] = {0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34,
                           0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
    SigMatch *temp = NULL;
    int i = 0;

    result = (DetectDceIfaceSetup(NULL, s, NULL, "12345678-1234-1234-1234-123456789ABC,=1,any_frag") == 0);

    if (s->match != NULL) {
        temp = s->match;
        did = temp->ctx;
        result &= 1;
        for (i = 0; i < 16; i++) {
            if (did->uuid[i] != test_uuid[i]) {
                result = 0;
                break;
            }
        }
    }

    result &= (did->version == 1);
    result &= (did->op == DETECT_DCE_IFACE_OP_EQ);
    result &= (did->any_frag == 1);

    SigFree(s);
    return result;
}

static int DetectDceIfaceTestParse10(void)
{
    Signature *s = SigAlloc();
    int result = 0;
    DetectDceIfaceData *did = NULL;
    uint8_t test_uuid[] = {0x12, 0x34, 0x56, 0x78, 0x12, 0x34, 0x12, 0x34, 0x12, 0x34,
                           0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
    SigMatch *temp = NULL;
    int i = 0;

    result = (DetectDceIfaceSetup(NULL, s, NULL, "12345678-1234-1234-1234-123456789ABC,!1,any_frag") == 0);

    if (s->match != NULL) {
        temp = s->match;
        did = temp->ctx;
        result &= 1;
        for (i = 0; i < 16; i++) {
            if (did->uuid[i] != test_uuid[i]) {
                result = 0;
                break;
            }
        }
    }

    result &= (did->version == 1);
    result &= (did->op == DETECT_DCE_IFACE_OP_NE);
    result &= (did->any_frag == 1);

    SigFree(s);
    return result;
}

static int DetectDceIfaceTestParse11(void)
{
    Signature *s = SigAlloc();
    int result = 1;

    result &= (DetectDceIfaceSetup(NULL, s, NULL, "12345678-1234-1234-1234-123456789ABC,>1,ay_frag") == -1);
    result &= (DetectDceIfaceSetup(NULL, s, NULL, "12345678-1234-1234-1234-12345679ABC,>1,any_frag") == -1);
    result &= (DetectDceIfaceSetup(NULL, s, NULL, "12345678-1234-1234-134-123456789ABC,>1,any_frag") == -1);
    result &= (DetectDceIfaceSetup(NULL, s, NULL, "12345678-123-124-1234-123456789ABC,>1,any_frag") == -1);
    result &= (DetectDceIfaceSetup(NULL, s, NULL, "1234568-1234-1234-1234-123456789ABC,>1,any_frag") == -1);
    result &= (DetectDceIfaceSetup(NULL, s, NULL, "12345678-1234-1234-1234-123456789ABC,>65536,any_frag") == -1);
    result &= (DetectDceIfaceSetup(NULL, s, NULL, "12345678-1234-1234-1234-123456789ABC,>=1,any_frag") == -1);

    SigFree(s);
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

#endif

}

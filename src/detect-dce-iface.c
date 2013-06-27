/* Copyright (C) 2007-2013 Open Information Security Foundation
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
 * Implements the dce_iface keyword.
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

#define DETECT_DCE_IFACE_PCRE_PARSE_ARGS "^\\s*([0-9a-zA-Z]{8}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{4}-[0-9a-zA-Z]{12})(?:\\s*,(<|>|=|!)([0-9]{1,5}))?(?:\\s*,(any_frag))?\\s*$"

static pcre *parse_regex = NULL;
static pcre_extra *parse_regex_study = NULL;

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
    sigmatch_table[DETECT_DCE_IFACE].AppLayerMatch = NULL;
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

    if ( (did = SCMalloc(sizeof(DetectDceIfaceData))) == NULL)
        goto error;
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
        /* Basically an UUID consists of 16 bytes split as follows -
         * x4x3x2x1-x6x5-x8x7-x10x9-x11x12x13x14x15x16.
         * The first 4 bytes represent an integer (x4x3x2x1), where
         * x4 is the high byte, and x1 is the lowe byte.
         * Similarly with x6x5, x8x7, and x10x9, all 3 being 2 bytes
         * wide.  Do note that x10x9 would be stored as big endian
         * internally.
         * The last sequence of bytes are stored linearly and are to be
         * read as such. */
        if (j < 4) {
            *((uint32_t *)did->uuid) |= hex_value << ((3 - j) * 8);
        } else if (j < 6) {
            *((uint16_t *)did->uuid + 2) |= hex_value << ((5 - j) * 8);
        } else if (j < 8) {
            *((uint16_t *)did->uuid + 3) |= hex_value << ((7 - j) * 8);
        } else if (j < 10) {
            *((uint16_t *)did->uuid + 4) |= hex_value << ((9 - j) * 8);
        } else {
            did->uuid[j] = hex_value;
        }
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

int DetectDceIfaceMatchVersion(uint16_t iv, DetectDceIfaceData *did)
{
    switch (did->op) {
        case DETECT_DCE_IFACE_OP_LT:
            if (!(iv < did->version))
                return 0;
            return 1;
        case DETECT_DCE_IFACE_OP_GT:
            if (!(iv > did->version))
                return 0;
            return 1;
        case DETECT_DCE_IFACE_OP_EQ:
            if (!(iv == did->version))
                return 0;
            return 1;
        case DETECT_DCE_IFACE_OP_NE:
            if (!(iv != did->version))
                return 0;
            return 1;
        default:
            return 1;
    }
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

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_DCE_IFACE_MATCH);

    if (s->alproto != ALPROTO_UNKNOWN && s->alproto != ALPROTO_DCERPC) {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "rule contains conflicting keywords.");
        goto error;
    }

    s->alproto = ALPROTO_DCERPC;
    /* Flagged the signature as to inspect the app layer data */
    s->flags |= SIG_FLAG_APPLAYER;
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

static int DetectDceIfaceTest01(void)
{
    SCEnter();

    Signature *s = SigAlloc();
    if (s == NULL)
        return 0;

    int result = 0;
    DetectDceIfaceData *did = NULL;
    SigMatch *temp = NULL;

    if (DetectDceIfaceSetup(NULL, s, "12345678-1234-1234-1234-123456789ABC") < 0)
        goto end;

    if (s->sm_lists[DETECT_SM_LIST_DCE_IFACE_MATCH] == NULL) {
        SCReturnInt(0);
    }

    temp = s->sm_lists[DETECT_SM_LIST_DCE_IFACE_MATCH];
    did = temp->ctx;
    if (did == NULL) {
        SCReturnInt(0);
    }

    if (*((uint32_t *)did->uuid) != 0x12345678 ||
        *((uint16_t *)did->uuid + 2) != 0x1234 ||
        *((uint16_t *)did->uuid + 3) != 0x1234 ||
        *((uint16_t *)did->uuid + 4) != 0x1234 ||
        did->uuid[10] != 0x12 || did->uuid[11] != 0x34 ||
        did->uuid[12] != 0x56 || did->uuid[13] != 0x78 ||
        did->uuid[14] != 0x9A || did->uuid[15] != 0xBC) {
        printf("failure 1\n");
        goto end;
    }

    if (did->version != 0)
        goto end;
    if (did->op != 0)
        goto end;
    if (did->any_frag != 0)
        goto end;

    result = 1;

 end:
    SigFree(s);
    SCReturnInt(result);
}

static int DetectDceIfaceTest02(void)
{
    SCEnter();

    Signature *s = SigAlloc();
    if (s == NULL)
        return 0;

    int result = 0;
    DetectDceIfaceData *did = NULL;
    SigMatch *temp = NULL;

    if (DetectDceIfaceSetup(NULL, s, "12345678-1234-1234-1234-123456789ABC,>1") < 0)
        goto end;

    if (s->sm_lists[DETECT_SM_LIST_DCE_IFACE_MATCH] == NULL) {
        SCReturnInt(0);
    }

    temp = s->sm_lists[DETECT_SM_LIST_DCE_IFACE_MATCH];
    did = temp->ctx;
    if (did == NULL) {
        SCReturnInt(0);
    }

    if (*((uint32_t *)did->uuid) != 0x12345678 ||
        *((uint16_t *)did->uuid + 2) != 0x1234 ||
        *((uint16_t *)did->uuid + 3) != 0x1234 ||
        *((uint16_t *)did->uuid + 4) != 0x1234 ||
        did->uuid[10] != 0x12 || did->uuid[11] != 0x34 ||
        did->uuid[12] != 0x56 || did->uuid[13] != 0x78 ||
        did->uuid[14] != 0x9A || did->uuid[15] != 0xBC) {
        printf("failure 1\n");
        goto end;
    }

    if (did->version != 1)
        goto end;
    if (did->op != DETECT_DCE_IFACE_OP_GT)
        goto end;
    if (did->any_frag != 0)
        goto end;

    result = 1;

 end:
    SigFree(s);
    SCReturnInt(result);
}

static int DetectDceIfaceTest03(void)
{
    SCEnter();

    Signature *s = SigAlloc();
    if (s == NULL)
        return 0;

    int result = 0;
    DetectDceIfaceData *did = NULL;
    SigMatch *temp = NULL;

    if (DetectDceIfaceSetup(NULL, s, "12345678-1234-1234-1234-123456789ABC,<10") < 0)
        goto end;

    if (s->sm_lists[DETECT_SM_LIST_DCE_IFACE_MATCH] == NULL) {
        SCReturnInt(0);
    }

    temp = s->sm_lists[DETECT_SM_LIST_DCE_IFACE_MATCH];
    did = temp->ctx;
    if (*((uint32_t *)did->uuid) != 0x12345678 ||
        *((uint16_t *)did->uuid + 2) != 0x1234 ||
        *((uint16_t *)did->uuid + 3) != 0x1234 ||
        *((uint16_t *)did->uuid + 4) != 0x1234 ||
        did->uuid[10] != 0x12 || did->uuid[11] != 0x34 ||
        did->uuid[12] != 0x56 || did->uuid[13] != 0x78 ||
        did->uuid[14] != 0x9A || did->uuid[15] != 0xBC) {
        printf("failure 1\n");
        goto end;
    }

    if (did->version != 10)
        goto end;
    if (did->op != DETECT_DCE_IFACE_OP_LT)
        goto end;
    if (did->any_frag != 0)
        goto end;

    result = 1;

 end:
    SigFree(s);
    SCReturnInt(result);
}

static int DetectDceIfaceTest04(void)
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

    if (s->sm_lists[DETECT_SM_LIST_DCE_IFACE_MATCH] == NULL)
        goto end;

    temp = s->sm_lists[DETECT_SM_LIST_DCE_IFACE_MATCH];
    did = temp->ctx;
    if (did == NULL)
        goto end;

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

    result = 1;

 end:
    SigFree(s);
    SCReturnInt(result);
}

static int DetectDceIfaceTest05(void)
{
    SCEnter();

    Signature *s = SigAlloc();
    int result = 0;
    DetectDceIfaceData *did = NULL;
    SigMatch *temp = NULL;

    if (DetectDceIfaceSetup(NULL, s, "12345678-1234-1234-1234-123456789ABC,=10") < 0)
        goto end;

    if (s->sm_lists[DETECT_SM_LIST_DCE_IFACE_MATCH] == NULL) {
        SCReturnInt(0);
    }

    temp = s->sm_lists[DETECT_SM_LIST_DCE_IFACE_MATCH];
    did = temp->ctx;
    if (did == NULL) {
        SCReturnInt(0);
    }

    if (*((uint32_t *)did->uuid) != 0x12345678 ||
        *((uint16_t *)did->uuid + 2) != 0x1234 ||
        *((uint16_t *)did->uuid + 3) != 0x1234 ||
        *((uint16_t *)did->uuid + 4) != 0x1234 ||
        did->uuid[10] != 0x12 || did->uuid[11] != 0x34 ||
        did->uuid[12] != 0x56 || did->uuid[13] != 0x78 ||
        did->uuid[14] != 0x9A || did->uuid[15] != 0xBC) {
        printf("failure 1\n");
        goto end;
    }

    if (did->version != 10)
        goto end;
    if (did->op != DETECT_DCE_IFACE_OP_EQ)
        goto end;
    if (did->any_frag != 0)
        goto end;

    result = 1;

 end:
    SigFree(s);
    SCReturnInt(result);
}

static int DetectDceIfaceTest06(void)
{
    SCEnter();

    Signature *s = SigAlloc();
    if (s == NULL)
        return 0;

    int result = 0;
    DetectDceIfaceData *did = NULL;
    SigMatch *temp = NULL;

    if (DetectDceIfaceSetup(NULL, s, "12345678-1234-1234-1234-123456789ABC,any_frag") < 0)
        goto end;

    if (s->sm_lists[DETECT_SM_LIST_DCE_IFACE_MATCH] == NULL) {
        SCReturnInt(0);
    }

    temp = s->sm_lists[DETECT_SM_LIST_DCE_IFACE_MATCH];
    did = temp->ctx;
    if (did == NULL) {
        SCReturnInt(0);
    }

    if (*((uint32_t *)did->uuid) != 0x12345678 ||
        *((uint16_t *)did->uuid + 2) != 0x1234 ||
        *((uint16_t *)did->uuid + 3) != 0x1234 ||
        *((uint16_t *)did->uuid + 4) != 0x1234 ||
        did->uuid[10] != 0x12 || did->uuid[11] != 0x34 ||
        did->uuid[12] != 0x56 || did->uuid[13] != 0x78 ||
        did->uuid[14] != 0x9A || did->uuid[15] != 0xBC) {
        printf("failure 1\n");
        goto end;
    }

    if (did->version != 0)
        goto end;
    if (did->op != 0)
        goto end;
    if (did->any_frag != 1)
        goto end;

    result = 1;

 end:
    SigFree(s);
    SCReturnInt(result);
}

static int DetectDceIfaceTest07(void)
{
    SCEnter();

    Signature *s = SigAlloc();
    if (s == NULL)
        return 0;

    int result = 0;
    DetectDceIfaceData *did = NULL;
    SigMatch *temp = NULL;

    if (DetectDceIfaceSetup(NULL, s, "12345678-1234-1234-1234-123456789ABC,>1,any_frag") < 0)
        goto end;

    if (s->sm_lists[DETECT_SM_LIST_DCE_IFACE_MATCH] == NULL) {
        SCReturnInt(0);
    }

    temp = s->sm_lists[DETECT_SM_LIST_DCE_IFACE_MATCH];
    did = temp->ctx;
    if (did == NULL) {
        SCReturnInt(0);
    }

    if (*((uint32_t *)did->uuid) != 0x12345678 ||
        *((uint16_t *)did->uuid + 2) != 0x1234 ||
        *((uint16_t *)did->uuid + 3) != 0x1234 ||
        *((uint16_t *)did->uuid + 4) != 0x1234 ||
        did->uuid[10] != 0x12 || did->uuid[11] != 0x34 ||
        did->uuid[12] != 0x56 || did->uuid[13] != 0x78 ||
        did->uuid[14] != 0x9A || did->uuid[15] != 0xBC) {
        printf("failure 1\n");
        goto end;
    }

    if (did->version != 1)
        goto end;
    if (did->op != DETECT_DCE_IFACE_OP_GT)
        goto end;
    if (did->any_frag != 1)
        goto end;

    result = 1;
 end:
    SigFree(s);
    SCReturnInt(result);
}

static int DetectDceIfaceTest08(void)
{
    Signature *s = SigAlloc();
    if (s == NULL)
        return 0;

    int result = 0;
    DetectDceIfaceData *did = NULL;
    SigMatch *temp = NULL;

    if (DetectDceIfaceSetup(NULL, s, "12345678-1234-1234-1234-123456789ABC,<1,any_frag") < 0)
        goto end;

    if (s->sm_lists[DETECT_SM_LIST_DCE_IFACE_MATCH] == NULL) {
        SCReturnInt(0);
    }

    temp = s->sm_lists[DETECT_SM_LIST_DCE_IFACE_MATCH];
    did = temp->ctx;
    if (did == NULL) {
        SCReturnInt(0);
    }

    if (*((uint32_t *)did->uuid) != 0x12345678 ||
        *((uint16_t *)did->uuid + 2) != 0x1234 ||
        *((uint16_t *)did->uuid + 3) != 0x1234 ||
        *((uint16_t *)did->uuid + 4) != 0x1234 ||
        did->uuid[10] != 0x12 || did->uuid[11] != 0x34 ||
        did->uuid[12] != 0x56 || did->uuid[13] != 0x78 ||
        did->uuid[14] != 0x9A || did->uuid[15] != 0xBC) {
        printf("failure 1\n");
        goto end;
    }

    if (did->version != 1)
        goto end;
    if (did->op != DETECT_DCE_IFACE_OP_LT)
        goto end;
    if (did->any_frag != 1)
        goto end;

    result = 1;

 end:
    SigFree(s);
    SCReturnInt(result);
}

static int DetectDceIfaceTest09(void)
{
    SCEnter();

    Signature *s = SigAlloc();
    if (s == NULL)
        return 0;

    int result = 0;
    DetectDceIfaceData *did = NULL;
    SigMatch *temp = NULL;

    if (DetectDceIfaceSetup(NULL, s, "12345678-1234-1234-1234-123456789ABC,=1,any_frag") < 0)
        goto end;

    temp = s->sm_lists[DETECT_SM_LIST_DCE_IFACE_MATCH];
    did = temp->ctx;
    if (did == NULL) {
        SCReturnInt(0);
    }

    if (*((uint32_t *)did->uuid) != 0x12345678 ||
        *((uint16_t *)did->uuid + 2) != 0x1234 ||
        *((uint16_t *)did->uuid + 3) != 0x1234 ||
        *((uint16_t *)did->uuid + 4) != 0x1234 ||
        did->uuid[10] != 0x12 || did->uuid[11] != 0x34 ||
        did->uuid[12] != 0x56 || did->uuid[13] != 0x78 ||
        did->uuid[14] != 0x9A || did->uuid[15] != 0xBC) {
        printf("failure 1\n");
        goto end;
    }

    if (did->version != 1)
        goto end;
    if (did->op != DETECT_DCE_IFACE_OP_EQ)
        goto end;
    if (did->any_frag != 1)
        goto end;

    result = 1;

 end:
    SigFree(s);
    SCReturnInt(result);
}

static int DetectDceIfaceTest10(void)
{
    SCEnter();

    Signature *s = SigAlloc();
    if (s == NULL)
        return 0;

    int result = 0;
    DetectDceIfaceData *did = NULL;
    SigMatch *temp = NULL;

    if (DetectDceIfaceSetup(NULL, s, "12345678-1234-1234-1234-123456789ABC,!1,any_frag") < 0)
        goto end;

    if (s->sm_lists[DETECT_SM_LIST_DCE_IFACE_MATCH] == NULL) {
        SCReturnInt(0);
    }

    temp = s->sm_lists[DETECT_SM_LIST_DCE_IFACE_MATCH];
    did = temp->ctx;
    if (did == NULL) {
        SCReturnInt(0);
    }

    if (*((uint32_t *)did->uuid) != 0x12345678 ||
        *((uint16_t *)did->uuid + 2) != 0x1234 ||
        *((uint16_t *)did->uuid + 3) != 0x1234 ||
        *((uint16_t *)did->uuid + 4) != 0x1234 ||
        did->uuid[10] != 0x12 || did->uuid[11] != 0x34 ||
        did->uuid[12] != 0x56 || did->uuid[13] != 0x78 ||
        did->uuid[14] != 0x9A || did->uuid[15] != 0xBC) {
        printf("failure 1\n");
        goto end;
    }

    if (did->version != 1)
        goto end;
    if (did->op != DETECT_DCE_IFACE_OP_NE)
        goto end;
    if (did->any_frag != 1)
        goto end;

    result = 1;

 end:
    SigFree(s);
    SCReturnInt(result);
}

static int DetectDceIfaceTest11(void)
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
static int DetectDceIfaceTest12(void)
{
    int result = 0;
    Signature *s = NULL;
    ThreadVars th_v;
    Packet *p = NULL;
    Flow f;
    TcpSession ssn;
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    struct DCERPCState *dcerpc_state = NULL;
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

    memset(&th_v, 0, sizeof(th_v));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
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
                                   "(msg:\"DCERPC\"; "
                                   "dce_iface:3919286a-b10c-11d0-9ba8-00c04fd92ef5,=0,any_frag; "
                                   "sid:1;)");
    if (s == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SCLogDebug("handling to_server chunk");

    r = AppLayerParse(NULL, &f, ALPROTO_DCERPC, STREAM_TOSERVER | STREAM_START,
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 matched but shouldn't have\n");
        goto end;
    }

    SCLogDebug("handling to_client chunk");

    r = AppLayerParse(NULL, &f, ALPROTO_DCERPC, STREAM_TOCLIENT, dcerpc_bindack,
                      dcerpc_bindack_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sid 1 matched, but shouldn't have: ");
        goto end;
    }

    r = AppLayerParse(NULL, &f, ALPROTO_DCERPC, STREAM_TOSERVER, dcerpc_request,
                      dcerpc_request_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sid 1 didn't matched, but should have: ");
        goto end;
    }

    result = 1;

end:
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
 * \test Test a valid dce_iface entry with a bind, bind_ack and 3 request/responses.
 */
static int DetectDceIfaceTest13(void)
{
    int result = 0;
    Signature *s = NULL;
    ThreadVars th_v;
    Packet *p = NULL;
    Flow f;
    TcpSession ssn;
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    struct DCERPCState *dcerpc_state = NULL;
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

    r = AppLayerParse(NULL, &f, ALPROTO_DCERPC, STREAM_TOSERVER | STREAM_START,
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

    r = AppLayerParse(NULL, &f, ALPROTO_DCERPC, STREAM_TOCLIENT, dcerpc_bindack,
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
    r = AppLayerParse(NULL, &f, ALPROTO_DCERPC, STREAM_TOSERVER, dcerpc_request1,
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
    r = AppLayerParse(NULL, &f, ALPROTO_DCERPC, STREAM_TOCLIENT, dcerpc_response1,
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
    r = AppLayerParse(NULL, &f, ALPROTO_DCERPC, STREAM_TOSERVER, dcerpc_request2,
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
    r = AppLayerParse(NULL, &f, ALPROTO_DCERPC, STREAM_TOCLIENT, dcerpc_response2,
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
    r = AppLayerParse(NULL, &f, ALPROTO_DCERPC, STREAM_TOSERVER, dcerpc_request3,
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
    r = AppLayerParse(NULL, &f, ALPROTO_DCERPC, STREAM_TOCLIENT | STREAM_EOF,
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
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    UTHFreePackets(&p, 1);
    return result;
}

/**
 * \test Test a valid dce_iface entry for a bind and bind_ack
 */
static int DetectDceIfaceTest14(void)
{
    int result = 0;
    Signature *s = NULL;
    ThreadVars th_v;
    Packet *p = NULL;
    Flow f;
    TcpSession ssn;
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    struct DCERPCState *dcerpc_state = NULL;
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

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
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

    r = AppLayerParse(NULL, &f, ALPROTO_DCERPC, STREAM_TOSERVER | STREAM_START,
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 matched but shouldn't have: ");
        goto end;
    }

    r = AppLayerParse(NULL, &f, ALPROTO_DCERPC, STREAM_TOCLIENT, dcerpc_bindack,
                      dcerpc_bindack_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1)) {
        printf("sig 1 matched but shouldn't have: ");
        goto end;
    }

    r = AppLayerParse(NULL, &f, ALPROTO_DCERPC, STREAM_TOSERVER, dcerpc_request,
                      dcerpc_request_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (!PacketAlertCheck(p, 1)) {
        printf("sig 1 matched but shouldn't have: ");
        goto end;
    }

    result = 1;

 end:
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}

#if 0
/**
 * \test Test a valid dce_iface entry for a bind and bind_ack
 */
static int DetectDceIfaceTest15(void)
{
    int result = 0;
    Signature *s = NULL;
    ThreadVars th_v;
    Packet *p = NULL;
    Flow f;
    TcpSession ssn;
    DetectEngineThreadCtx *det_ctx = NULL;
    DetectEngineCtx *de_ctx = NULL;
    struct DCERPCState *dcerpc_state = NULL;
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

    memset(&th_v, 0, sizeof(th_v));
    memset(&p, 0, sizeof(p));
    memset(&f, 0, sizeof(f));
    memset(&ssn, 0, sizeof(ssn));

    p = UTHBuildPacket(NULL, 0, IPPROTO_TCP);

    FLOW_INITIALIZE(&f);
    f.protoctx = (void *)&ssn;
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

    r = AppLayerParse(NULL, &f, ALPROTO_DCERPC, STREAM_TOSERVER | STREAM_START,
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

    /* do detect */
    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);

    if (PacketAlertCheck(p, 1))
        goto end;
    if (PacketAlertCheck(p, 2))
        goto end;

    r = AppLayerParse(NULL, &f, ALPROTO_DCERPC, STREAM_TOCLIENT, dcerpc_bindack,
                      dcerpc_bindack_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

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

    r = AppLayerParse(NULL, &f, ALPROTO_DCERPC, STREAM_TOSERVER, dcerpc_alter_context,
                      dcerpc_alter_context_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

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

    r = AppLayerParse(NULL, &f, ALPROTO_DCERPC, STREAM_TOCLIENT, dcerpc_alter_context_resp,
                      dcerpc_alter_context_resp_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

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

    r = AppLayerParse(NULL, &f, ALPROTO_DCERPC, STREAM_TOSERVER, dcerpc_request1,
                      dcerpc_request1_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

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

    r = AppLayerParse(NULL, &f, ALPROTO_DCERPC, STREAM_TOCLIENT, dcerpc_response1,
                      dcerpc_response1_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

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

    r = AppLayerParse(NULL, &f, ALPROTO_DCERPC, STREAM_TOSERVER, dcerpc_request2,
                      dcerpc_request2_len);
    if (r != 0) {
        SCLogDebug("AppLayerParse for dcerpc failed.  Returned %" PRId32, r);
        goto end;
    }

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
    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);

    StreamTcpFreeConfig(TRUE);
    FLOW_DESTROY(&f);
    UTHFreePackets(&p, 1);
    return result;
}
#endif /* #if 0 */

#endif

void DetectDceIfaceRegisterTests(void)
{

#ifdef UNITTESTS
    UtRegisterTest("DetectDceIfaceTest01", DetectDceIfaceTest01, 1);
    UtRegisterTest("DetectDceIfaceTest02", DetectDceIfaceTest02, 1);
    UtRegisterTest("DetectDceIfaceTest03", DetectDceIfaceTest03, 1);
    UtRegisterTest("DetectDceIfaceTest04", DetectDceIfaceTest04, 1);
    UtRegisterTest("DetectDceIfaceTest05", DetectDceIfaceTest05, 1);
    UtRegisterTest("DetectDceIfaceTest06", DetectDceIfaceTest06, 1);
    UtRegisterTest("DetectDceIfaceTest07", DetectDceIfaceTest07, 1);
    UtRegisterTest("DetectDceIfaceTest08", DetectDceIfaceTest08, 1);
    UtRegisterTest("DetectDceIfaceTest09", DetectDceIfaceTest09, 1);
    UtRegisterTest("DetectDceIfaceTest10", DetectDceIfaceTest10, 1);
    UtRegisterTest("DetectDceIfaceTest11", DetectDceIfaceTest11, 1);
    UtRegisterTest("DetectDceIfaceTest12", DetectDceIfaceTest12, 1);
    UtRegisterTest("DetectDceIfaceTest13", DetectDceIfaceTest13, 1);
    UtRegisterTest("DetectDceIfaceTest14", DetectDceIfaceTest14, 1);
    /* the reason we disabled this is because we don't support
     * retaining older uuids in case we immediatley see an
     * alter context or a bind with an older assoc group id. */
#if 0
    UtRegisterTest("DetectDceIfaceTest15", DetectDceIfaceTest15, 1);
#endif
#endif

    return;
}

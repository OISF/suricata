/* Copyright (C) 2007-2022 Open Information Security Foundation
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
 * \author Brian Rectanus <brectanu@gmail.com>
 *
 * Implements the ip_proto keyword
 */

#include "suricata-common.h"

#include "detect-ipproto.h"

#include "detect-parse.h"

#include "util-byte.h"
#include "util-proto-name.h"

#ifdef UNITTESTS
#include "util-debug.h"
#include "util-unittest-helper.h"
#include "util-unittest.h"
#include "detect-engine-address.h"
#include "detect-engine-siggroup.h"
#include "detect-engine-build.h"
#include "detect-engine-mpm.h"
#include "detect-engine.h"
#include "detect.h"
#include "decode.h"
#endif
/**
 * \brief Regex for parsing our options
 */
#define PARSE_REGEX  "^([!<>]?)\\s*([^\\s]+)$"

static DetectParseRegex parse_regex;

static int DetectIPProtoSetup(DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectIPProtoRegisterTests(void);
#endif
static void DetectIPProtoFree(DetectEngineCtx *, void *);

void DetectIPProtoRegister(void)
{
    sigmatch_table[DETECT_IPPROTO].name = "ip_proto";
    sigmatch_table[DETECT_IPPROTO].desc = "match on the IP protocol in the packet-header";
    sigmatch_table[DETECT_IPPROTO].url = "/rules/header-keywords.html#ip-proto";
    sigmatch_table[DETECT_IPPROTO].Match = NULL;
    sigmatch_table[DETECT_IPPROTO].Setup = DetectIPProtoSetup;
    sigmatch_table[DETECT_IPPROTO].Free  = DetectIPProtoFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_IPPROTO].RegisterTests = DetectIPProtoRegisterTests;
#endif
    sigmatch_table[DETECT_IPPROTO].flags = SIGMATCH_QUOTES_OPTIONAL;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
}

/**
 * \internal
 * \brief Parse ip_proto options string.
 *
 * \param optstr Options string to parse
 *
 * \return New ip_proto data structure
 */
static DetectIPProtoData *DetectIPProtoParse(const char *optstr)
{
    DetectIPProtoData *data = NULL;
    char *args[2] = { NULL, NULL };
    int ret = 0, res = 0;
    size_t pcre2_len;
    int i;
    const char *str_ptr;

    /* Execute the regex and populate args with captures. */
    ret = DetectParsePcreExec(&parse_regex, optstr, 0, 0);
    if (ret != 3) {
        SCLogError(SC_ERR_PCRE_MATCH, "pcre_exec parse error, ret"
                   "%" PRId32 ", string %s", ret, optstr);
        goto error;
    }

    for (i = 0; i < (ret - 1); i++) {
        res = pcre2_substring_get_bynumber(
                parse_regex.match, i + 1, (PCRE2_UCHAR8 **)&str_ptr, &pcre2_len);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre2_substring_get_bynumber failed");
            goto error;
        }
        args[i] = (char *)str_ptr;
    }

    /* Initialize the data */
    data = SCMalloc(sizeof(DetectIPProtoData));
    if (unlikely(data == NULL))
        goto error;
    data->op = DETECT_IPPROTO_OP_EQ;
    data->proto = 0;

    /* Operator */
    if (*(args[0]) != '\0') {
        data->op = *(args[0]);
    }

    /* Protocol name/number */
    if (!isdigit((unsigned char)*(args[1]))) {
        uint8_t proto;
        if (!SCGetProtoByName(args[1], &proto)) {
            SCLogError(SC_ERR_INVALID_VALUE, "Unknown protocol name: \"%s\"", str_ptr);
            goto error;
        }
        data->proto = proto;
    }
    else {
        if (StringParseUint8(&data->proto, 10, 0, args[1]) <= 0) {
            SCLogError(SC_ERR_INVALID_VALUE, "Malformed protocol number: %s",
                       str_ptr);
            goto error;
        }
    }

    for (i = 0; i < (ret - 1); i++){
        if (args[i] != NULL)
            pcre2_substring_free((PCRE2_UCHAR8 *)args[i]);
    }

    return data;

error:
    for (i = 0; i < (ret - 1) && i < 2; i++){
        if (args[i] != NULL)
            pcre2_substring_free((PCRE2_UCHAR8 *)args[i]);
    }
    if (data != NULL)
        SCFree(data);

    return NULL;
}

static int DetectIPProtoTypePresentForOP(Signature *s, uint8_t op)
{
    SigMatch *sm = s->init_data->smlists[DETECT_SM_LIST_MATCH];
    DetectIPProtoData *data;

    while (sm != NULL) {
        if (sm->type == DETECT_IPPROTO) {
            data = (DetectIPProtoData *)sm->ctx;
            if (data->op == op)
                return 1;
        }
        sm = sm->next;
    }

    return 0;
}

/**
 * \internal
 * \brief Setup ip_proto keyword.
 *
 * \param de_ctx Detection engine context
 * \param s Signature
 * \param optstr Options string
 *
 * \return Non-zero on error
 */
static int DetectIPProtoSetup(DetectEngineCtx *de_ctx, Signature *s, const char *optstr)
{
    SigMatch *sm = NULL;
    int i;

    DetectIPProtoData *data = DetectIPProtoParse(optstr);
    if (data == NULL) {
        return -1;
    }

    /* Reset our "any" (or "ip") state: for ipv4, ipv6 and ip cases, the bitfield
     * s->proto.proto have all bit set to 1 to be able to match any protocols. ipproto
     * will refined the protocol list and thus it needs to reset the bitfield to zero
     * before setting the value specified by the ip_proto keyword.
     */
    if (s->proto.flags & (DETECT_PROTO_ANY | DETECT_PROTO_IPV6 | DETECT_PROTO_IPV4)) {
        s->proto.flags &= ~DETECT_PROTO_ANY;
        memset(s->proto.proto, 0x00, sizeof(s->proto.proto));
        s->init_data->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    } else {
        /* The ipproto engine has a relationship with the protocol that is
         * set after the action and also the app protocol(that can also be
         * set through the app-layer-protocol.
         * An ip_proto keyword can be used only with alert ip, which if
         * not true we error out on the sig.  And hence the init_flag to
         * indicate this. */
        if (!(s->init_data->init_flags & SIG_FLAG_INIT_FIRST_IPPROTO_SEEN)) {
            SCLogError(SC_ERR_INVALID_SIGNATURE, "Signature can use "
                       "ip_proto keyword only when we use alert ip, "
                       "in which case the _ANY flag is set on the sig "
                       "and the if condition should match.");
            goto error;
        }
    }

    int eq_set = DetectIPProtoTypePresentForOP(s, DETECT_IPPROTO_OP_EQ);
    int gt_set = DetectIPProtoTypePresentForOP(s, DETECT_IPPROTO_OP_GT);
    int lt_set = DetectIPProtoTypePresentForOP(s, DETECT_IPPROTO_OP_LT);
    int not_set = DetectIPProtoTypePresentForOP(s, DETECT_IPPROTO_OP_NOT);

    switch (data->op) {
        case DETECT_IPPROTO_OP_EQ:
            if (eq_set || gt_set || lt_set || not_set) {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "can't use a eq "
                           "ipproto without any operators attached to "
                           "them in the same sig");
                goto error;
            }
            s->proto.proto[data->proto / 8] |= 1 << (data->proto % 8);
            break;

        case DETECT_IPPROTO_OP_GT:
            if (eq_set || gt_set) {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "can't use a eq or gt "
                           "ipproto along with a greater than ipproto in the "
                           "same sig ");
                goto error;
            }
            if (!lt_set && !not_set) {
                s->proto.proto[data->proto / 8] = (uint8_t)(0xfe << (data->proto % 8));
                for (i = (data->proto / 8) + 1; i < (256 / 8); i++) {
                    s->proto.proto[i] = 0xff;
                }
            } else if (lt_set && !not_set) {
                SigMatch *temp_sm = s->init_data->smlists[DETECT_SM_LIST_MATCH];
                while (temp_sm != NULL) {
                    if (temp_sm->type == DETECT_IPPROTO) {
                        break;
                    }
                    temp_sm = temp_sm->next;
                }
                if (temp_sm != NULL) {
                  DetectIPProtoData *data_temp = (DetectIPProtoData *)temp_sm->ctx;
                    if (data_temp->proto <= data->proto) {
                        SCLogError(SC_ERR_INVALID_SIGNATURE, "can't have "
                                "both gt and lt ipprotos, with the lt being "
                                "lower than gt value");
                        goto error;
                    } else {
                        for (i = 0; i < (data->proto / 8); i++) {
                            s->proto.proto[i] = 0;
                        }
                        s->proto.proto[data->proto / 8] &= 0xfe << (data->proto % 8);
                        for (i = (data->proto / 8) + 1; i < (256 / 8); i++) {
                            s->proto.proto[i] &= 0xff;
                        }
                    }
                }
            } else if (!lt_set && not_set) {
                for (i = 0; i < (data->proto / 8); i++) {
                    s->proto.proto[i] = 0;
                }
                s->proto.proto[data->proto / 8] &= 0xfe << (data->proto % 8);
                for (i = (data->proto / 8) + 1; i < (256 / 8); i++) {
                    s->proto.proto[i] &= 0xff;
                }
            } else {
                DetectIPProtoData *data_temp;
                SigMatch *temp_sm = s->init_data->smlists[DETECT_SM_LIST_MATCH];
                while (temp_sm != NULL) {
                    if (temp_sm->type == DETECT_IPPROTO &&
                        ((DetectIPProtoData *)temp_sm->ctx)->op == DETECT_IPPROTO_OP_LT) {
                        break;
                    }
                    temp_sm = temp_sm->next;
                }
                if (temp_sm != NULL) {
                    data_temp = (DetectIPProtoData *)temp_sm->ctx;
                    if (data_temp->proto <= data->proto) {
                        SCLogError(SC_ERR_INVALID_SIGNATURE, "can't have "
                                "both gt and lt ipprotos, with the lt being "
                                "lower than gt value");
                        goto error;
                    } else {
                        for (i = 0; i < (data->proto / 8); i++) {
                            s->proto.proto[i] = 0;
                        }
                        s->proto.proto[data->proto / 8] &= 0xfe << (data->proto % 8);
                        for (i = (data->proto / 8) + 1; i < (256 / 8); i++) {
                            s->proto.proto[i] &= 0xff;
                        }
                    }
                }
            }
            break;

        case DETECT_IPPROTO_OP_LT:
            if (eq_set || lt_set) {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "can't use a eq or lt "
                           "ipproto along with a less than ipproto in the "
                           "same sig ");
                goto error;
            }
            if (!gt_set && !not_set) {
                for (i = 0; i < (data->proto / 8); i++) {
                    s->proto.proto[i] = 0xff;
                }
                s->proto.proto[data->proto / 8] = (uint8_t)(~(0xff << (data->proto % 8)));
            } else if (gt_set && !not_set) {
                SigMatch *temp_sm = s->init_data->smlists[DETECT_SM_LIST_MATCH];
                while (temp_sm != NULL) {
                    if (temp_sm->type == DETECT_IPPROTO) {
                        break;
                    }
                    temp_sm = temp_sm->next;
                }
                if (temp_sm != NULL) {
                  DetectIPProtoData *data_temp = (DetectIPProtoData *)temp_sm->ctx;
                    if (data_temp->proto >= data->proto) {
                        SCLogError(SC_ERR_INVALID_SIGNATURE, "can't use a have "
                                "both gt and lt ipprotos, with the lt being "
                                "lower than gt value");
                        goto error;
                    } else {
                        for (i = 0; i < (data->proto / 8); i++) {
                            s->proto.proto[i] &= 0xff;
                        }
                        s->proto.proto[data->proto / 8] &= ~(0xff << (data->proto % 8));
                        for (i = (data->proto / 8) + 1; i < 256 / 8; i++) {
                            s->proto.proto[i] = 0;
                        }
                    }
                }
            } else if (!gt_set && not_set) {
                for (i = 0; i < (data->proto / 8); i++) {
                    s->proto.proto[i] &= 0xFF;
                }
                s->proto.proto[data->proto / 8] &= ~(0xff << (data->proto % 8));
                for (i = (data->proto / 8) + 1; i < (256 / 8); i++) {
                    s->proto.proto[i] = 0;
                }
            } else {
                DetectIPProtoData *data_temp;
                SigMatch *temp_sm = s->init_data->smlists[DETECT_SM_LIST_MATCH];
                while (temp_sm != NULL) {
                    if (temp_sm->type == DETECT_IPPROTO &&
                        ((DetectIPProtoData *)temp_sm->ctx)->op == DETECT_IPPROTO_OP_GT) {
                        break;
                    }
                    temp_sm = temp_sm->next;
                }
                if (temp_sm != NULL) {
                  data_temp = (DetectIPProtoData *)temp_sm->ctx;
                    if (data_temp->proto >= data->proto) {
                        SCLogError(SC_ERR_INVALID_SIGNATURE, "can't have "
                                "both gt and lt ipprotos, with the lt being "
                                "lower than gt value");
                        goto error;
                    } else {
                        for (i = 0; i < (data->proto / 8); i++) {
                            s->proto.proto[i] &= 0xFF;
                        }
                        s->proto.proto[data->proto / 8] &= ~(0xff << (data->proto % 8));
                        for (i = (data->proto / 8) + 1; i < (256 / 8); i++) {
                            s->proto.proto[i] = 0;
                        }
                    }
                }
            }
            break;

        case DETECT_IPPROTO_OP_NOT:
            if (eq_set) {
                SCLogError(SC_ERR_INVALID_SIGNATURE, "can't use a eq "
                           "ipproto along with a not ipproto in the "
                           "same sig ");
                goto error;
            }
            if (!gt_set && !lt_set && !not_set) {
                for (i = 0; i < (data->proto / 8); i++) {
                    s->proto.proto[i] = 0xff;
                }
                s->proto.proto[data->proto / 8] = (uint8_t)(~(1 << (data->proto % 8)));
                for (i = (data->proto / 8) + 1; i < (256 / 8); i++) {
                    s->proto.proto[i] = 0xff;
                }
            } else {
                for (i = 0; i < (data->proto / 8); i++) {
                    s->proto.proto[i] &= 0xff;
                }
                s->proto.proto[data->proto / 8] &= ~(1 << (data->proto % 8));
                for (i = (data->proto / 8) + 1; i < (256 / 8); i++) {
                    s->proto.proto[i] &= 0xff;
                }
            }
            break;
    }

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;
    sm->type = DETECT_IPPROTO;
    sm->ctx = (void *)data;
    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_MATCH);
    s->flags |= SIG_FLAG_REQUIRE_PACKET;

    return 0;

 error:

    DetectIPProtoFree(de_ctx, data);
    return -1;
}


void DetectIPProtoRemoveAllSMs(DetectEngineCtx *de_ctx, Signature *s)
{
    SigMatch *sm = s->init_data->smlists[DETECT_SM_LIST_MATCH];

    while (sm != NULL) {
        if (sm->type != DETECT_IPPROTO) {
            sm = sm->next;
            continue;
        }
        SigMatch *tmp_sm = sm->next;
        SigMatchRemoveSMFromList(s, sm, DETECT_SM_LIST_MATCH);
        SigMatchFree(de_ctx, sm);
        sm = tmp_sm;
    }

    return;
}

static void DetectIPProtoFree(DetectEngineCtx *de_ctx, void *ptr)
{
    DetectIPProtoData *data = (DetectIPProtoData *)ptr;
    if (data) {
        SCFree(data);
    }
}

/* UNITTESTS */
#ifdef UNITTESTS

/**
 * \test DetectIPProtoTestParse01 is a test for an invalid proto number
 */
static int DetectIPProtoTestParse01(void)
{
    DetectIPProtoData *data = DetectIPProtoParse("999");
    FAIL_IF_NOT(data == NULL);
    PASS;
}

/**
 * \test DetectIPProtoTestParse02 is a test for an invalid proto name
 */
static int DetectIPProtoTestParse02(void)
{
    DetectIPProtoData *data = DetectIPProtoParse("foobarbooeek");
    FAIL_IF_NOT(data == NULL);
    PASS;
}

/**
 * \test DetectIPProtoTestSetup01 is a test for a protocol number
 */
static int DetectIPProtoTestSetup01(void)
{
    const char *value_str = "14";
    int value;
    FAIL_IF(StringParseInt32(&value, 10, 0, (const char *)value_str) < 0);
    int i;

    Signature *sig = SigAlloc();
    FAIL_IF_NULL(sig);

    sig->init_data->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    DetectIPProtoSetup(NULL, sig, value_str);
    for (i = 0; i < (value / 8); i++) {
        FAIL_IF(sig->proto.proto[i] != 0);
    }
    FAIL_IF(sig->proto.proto[value / 8] != 0x40);
    for (i = (value / 8) + 1; i < (256 / 8); i++) {
        FAIL_IF(sig->proto.proto[i] != 0);
    }
    SigFree(NULL, sig);
    PASS;
}

/**
 * \test DetectIPProtoTestSetup02 is a test for a protocol name
 */
static int DetectIPProtoTestSetup02(void)
{
    int result = 0;
    Signature *sig = NULL;
    const char *value_str = "tcp";
    struct protoent *pent = getprotobyname(value_str);
    if (pent == NULL) {
        goto end;
    }
    uint8_t value = (uint8_t)pent->p_proto;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_data->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    DetectIPProtoSetup(NULL, sig, value_str);
    for (i = 0; i < (value / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value / 8] != 0x40) {
        goto end;
    }
    for (i = (value / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    if (sig != NULL)
        SigFree(NULL, sig);
    return result;
}

/**
 * \test DetectIPProtoTestSetup03 is a test for a < operator
 */
static int DetectIPProtoTestSetup03(void)
{
    int result = 0;
    Signature *sig;
    const char *value_str = "<14";
    int value = 14;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_data->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    DetectIPProtoSetup(NULL, sig, value_str);
    for (i = 0; i < (value / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value / 8] != 0x3F) {
        goto end;
    }
    for (i = (value / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(NULL, sig);
    return result;
}

/**
 * \test DetectIPProtoTestSetup04 is a test for a > operator
 */
static int DetectIPProtoTestSetup04(void)
{
    int result = 0;
    Signature *sig;
    const char *value_str = ">14";
    int value = 14;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_data->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    DetectIPProtoSetup(NULL, sig, value_str);
    for (i = 0; i < (value / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value / 8] != 0x80) {
        goto end;
    }
    for (i = (value / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }

    result = 1;

 end:
    SigFree(NULL, sig);
    return result;
}

/**
 * \test DetectIPProtoTestSetup05 is a test for a ! operator
 */
static int DetectIPProtoTestSetup05(void)
{
    int result = 0;
    Signature *sig;
    const char *value_str = "!14";
    int value = 14;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_data->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    DetectIPProtoSetup(NULL, sig, value_str);
    for (i = 0; i < (value / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value / 8] != 0xBF) {
        goto end;
    }
    for (i = (value / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }

    result = 1;

 end:
    SigFree(NULL, sig);
    return result;
}

/**
 * \test Negative test.
 */
static int DetectIPProtoTestSetup06(void)
{
    int result = 0;
    Signature *sig;
    const char *value1_str = "14";
    const char *value2_str = "15";

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_data->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != -1)
        goto end;

    result = 1;

 end:
    SigFree(NULL, sig);
    return result;
}

/**
 * \test Negative test.
 */
static int DetectIPProtoTestSetup07(void)
{
    int result = 0;
    Signature *sig;
    const char *value1_str = "14";
    const char *value2_str = "<15";

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_data->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != -1)
        goto end;

    result = 1;

 end:
    SigFree(NULL, sig);
    return result;
}

/**
 * \test Negative test.
 */
static int DetectIPProtoTestSetup08(void)
{
    int result = 0;
    Signature *sig;
    const char *value1_str = "14";
    const char *value2_str = ">15";

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_data->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != -1)
        goto end;

    result = 1;

 end:
    SigFree(NULL, sig);
    return result;
}

/**
 * \test Negative test.
 */
static int DetectIPProtoTestSetup09(void)
{
    int result = 0;
    Signature *sig;
    const char *value1_str = "14";
    const char *value2_str = "!15";

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_data->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != -1)
        goto end;

    result = 1;

 end:
    SigFree(NULL, sig);
    return result;
}

/**
 * \test Negative test.
 */
static int DetectIPProtoTestSetup10(void)
{
    int result = 0;
    Signature *sig;
    const char *value1_str = ">14";
    const char *value2_str = "15";

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_data->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != -1)
        goto end;

    result = 1;

 end:
    SigFree(NULL, sig);
    return result;
}

/**
 * \test Negative test.
 */
static int DetectIPProtoTestSetup11(void)
{
    int result = 0;
    Signature *sig;
    const char *value1_str = "<14";
    const char *value2_str = "15";

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_data->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != -1)
        goto end;

    result = 1;

 end:
    SigFree(NULL, sig);
    return result;
}

/**
 * \test Negative test.
 */
static int DetectIPProtoTestSetup12(void)
{
    int result = 0;
    Signature *sig;
    const char *value1_str = "!14";
    const char *value2_str = "15";

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_data->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != -1)
        goto end;

    result = 1;

 end:
    SigFree(NULL, sig);
    return result;
}

/**
 * \test Negative test.
 */
static int DetectIPProtoTestSetup13(void)
{
    int result = 0;
    Signature *sig;
    const char *value1_str = ">14";
    const char *value2_str = ">15";

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_data->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != -1)
        goto end;

    result = 1;

 end:
    SigFree(NULL, sig);
    return result;
}

static int DetectIPProtoTestSetup14(void)
{
    int result = 0;
    Signature *sig;
    const char *value1_str = "<14";
    const char *value2_str = "<15";

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_data->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != -1)
        goto end;

    result = 1;

 end:
    SigFree(NULL, sig);
    return result;
}

static int DetectIPProtoTestSetup15(void)
{
    int result = 0;
    Signature *sig;
    const char *value1_str = "<14";
    int value1 = 14;
    const char *value2_str = ">34";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_data->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x3F) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (DetectIPProtoSetup(NULL, sig, value2_str) == 0)
        goto end;

    result = 1;

 end:
    SigFree(NULL, sig);
    return result;

}

static int DetectIPProtoTestSetup16(void)
{
    int result = 0;
    Signature *sig;
    const char *value1_str = "<14";
    const char *value2_str = ">34";
    int value2 = 34;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_data->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < (value2 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0xF8) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (DetectIPProtoSetup(NULL, sig, value1_str) == 0)
        goto end;

    result = 1;

 end:
    SigFree(NULL, sig);
    return result;

}

static int DetectIPProtoTestSetup17(void)
{
    int result = 0;
    Signature *sig;
    const char *value1_str = "<11";
    int value1 = 11;
    const char *value2_str = ">13";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_data->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x07) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (DetectIPProtoSetup(NULL, sig, value2_str) == 0)
        goto end;

    result = 1;

 end:
    SigFree(NULL, sig);
    return result;

}

static int DetectIPProtoTestSetup18(void)
{
    int result = 0;
    Signature *sig;
    const char *value1_str = "<11";
    const char *value2_str = ">13";
    int value2 = 13;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_data->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < (value2 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0xC0) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (DetectIPProtoSetup(NULL, sig, value1_str) == 0)
        goto end;

    result = 1;

 end:
    SigFree(NULL, sig);
    return result;

}

static int DetectIPProtoTestSetup19(void)
{
    int result = 0;
    Signature *sig;
    const char *value1_str = "<11";
    int value1 = 11;
    const char *value2_str = "!13";
    const char *value3_str = ">36";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_data->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x07) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (DetectIPProtoSetup(NULL, sig, value3_str) == 0)
        goto end;

    result = 1;

 end:
    SigFree(NULL, sig);
    return result;
}

static int DetectIPProtoTestSetup20(void)
{
    int result = 0;
    Signature *sig;
    const char *value1_str = "<11";
    int value1 = 11;
    const char *value3_str = ">36";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_data->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x07) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (DetectIPProtoSetup(NULL, sig, value3_str) == 0)
        goto end;

    result = 1;

 end:
    SigFree(NULL, sig);
    return result;
}

static int DetectIPProtoTestSetup21(void)
{
    int result = 0;
    Signature *sig;
    const char *value1_str = "<11";
    int value1 = 11;
    const char *value2_str = "!13";
    const char *value3_str = ">36";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_data->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x07) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (DetectIPProtoSetup(NULL, sig, value3_str) == 0)
        goto end;

    result = 1;

 end:
    SigFree(NULL, sig);
    return result;
}

static int DetectIPProtoTestSetup22(void)
{
    int result = 0;
    Signature *sig;
    const char *value1_str = "<11";
    const char *value2_str = "!13";
    const char *value3_str = ">36";
    int value3 = 36;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_data->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    for (i = 0; i < (value3 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value3 / 8] != 0xE0) {
        goto end;
    }
    for (i = (value3 / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (DetectIPProtoSetup(NULL, sig, value1_str) == 0)
        goto end;

    result = 1;

 end:
    SigFree(NULL, sig);
    return result;
}

static int DetectIPProtoTestSetup23(void)
{
    int result = 0;
    Signature *sig;
    const char *value1_str = "<11";
    const char *value3_str = ">36";
    int value3 = 36;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_data->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    for (i = 0; i < (value3 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value3 / 8] != 0xE0) {
        goto end;
    }
    for (i = (value3 / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (DetectIPProtoSetup(NULL, sig, value1_str) == 0)
        goto end;

    result = 1;

 end:
    SigFree(NULL, sig);
    return result;
}

static int DetectIPProtoTestSetup24(void)
{
    int result = 0;
    Signature *sig;
    const char *value1_str = "<11";
    const char *value2_str = "!13";
    const char *value3_str = ">36";
    int value3 = 36;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_data->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < (value3 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value3 / 8] != 0xE0) {
        goto end;
    }
    for (i = (value3 / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (DetectIPProtoSetup(NULL, sig, value1_str) == 0)
        goto end;

    result = 1;

 end:
    SigFree(NULL, sig);
    return result;
}

static int DetectIPProtoTestSetup33(void)
{
    int result = 0;
    Signature *sig;
    const char *value1_str = "<11";
    int value1 = 11;
    const char *value2_str = "!34";
    const char *value3_str = ">36";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_data->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x07) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (DetectIPProtoSetup(NULL, sig, value3_str) == 0)
        goto end;

    result = 1;

 end:
    SigFree(NULL, sig);
    return result;
}

static int DetectIPProtoTestSetup34(void)
{
    int result = 0;
    Signature *sig;
    const char *value1_str = "<11";
    int value1 = 11;
    const char *value2_str = "!34";
    const char *value3_str = ">36";
    int value3 = 36;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_data->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value3 / 8] != 0xE0) {
        goto end;
    }
    for (i = (value3 / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (DetectIPProtoSetup(NULL, sig, value1_str) == 0)
        goto end;

    result = 1;

 end:
    SigFree(NULL, sig);
    return result;
}

static int DetectIPProtoTestSetup36(void)
{
    int result = 0;
    Signature *sig;
    const char *value1_str = "<11";
    const char *value2_str = "!34";
    const char *value3_str = ">36";
    int value3 = 36;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_data->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < (value3 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value3 / 8] != 0xE0) {
        goto end;
    }
    for (i = (value3 / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (DetectIPProtoSetup(NULL, sig, value1_str) == 0)
        goto end;

    result = 1;

 end:
    SigFree(NULL, sig);
    return result;
}

static int DetectIPProtoTestSetup43(void)
{
    int result = 0;
    Signature *sig;
    const char *value1_str = "!4";
    int value1 = 4;
    const char *value2_str = "<13";
    int value2 = 13;
    const char *value3_str = ">34";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_data->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (sig->proto.proto[value1 / 8] != 0xEF) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < (value2 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0x1F) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (DetectIPProtoSetup(NULL, sig, value3_str) == 0)
        goto end;

    result = 1;

 end:
    SigFree(NULL, sig);
    return result;
}

static int DetectIPProtoTestSetup44(void)
{
    int result = 0;
    Signature *sig;
    const char *value1_str = "!4";
    const char *value2_str = "<13";
    const char *value3_str = ">34";
    int value3 = 34;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_data->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    for (i = 0; i < (value3 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value3 / 8] != 0xF8) {
        goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (DetectIPProtoSetup(NULL, sig, value2_str) == 0)
        goto end;

    result = 1;

 end:
    SigFree(NULL, sig);
    return result;
}

static int DetectIPProtoTestSetup45(void)
{
    int result = 0;
    Signature *sig;
    const char *value1_str = "!4";
    int value1 = 4;
    const char *value2_str = "<13";
    int value2 = 13;
    const char *value3_str = ">34";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_data->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (sig->proto.proto[value1 / 8] != 0xEF) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < (value2 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0x1F) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (DetectIPProtoSetup(NULL, sig, value3_str) == 0)
        goto end;

    result = 1;

 end:
    SigFree(NULL, sig);
    return result;
}

static int DetectIPProtoTestSetup56(void)
{
    int result = 0;
    Signature *sig;
    const char *value1_str = "<13";
    int value1 = 13;
    const char *value2_str = ">34";
    const char *value3_str = "!37";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_data->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x1F) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (DetectIPProtoSetup(NULL, sig, value2_str) == 0)
        goto end;

    result = 1;

 end:
    SigFree(NULL, sig);
    return result;
}

static int DetectIPProtoTestSetup75(void)
{
    int result = 0;
    Signature *sig;
    const char *value1_str = "!8";
    const char *value2_str = ">10";
    int value2 = 10;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_data->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < (value2 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0xF8) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }

    result = 1;

 end:
    SigFree(NULL, sig);
    return result;
}

static int DetectIPProtoTestSetup76(void)
{
    int result = 0;
    Signature *sig;
    const char *value1_str = "!8";
    const char *value2_str = ">10";
    int value2 = 10;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_data->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    for (i = 0; i < (value2 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0xF8) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }

    result = 1;

 end:
    SigFree(NULL, sig);
    return result;
}

static int DetectIPProtoTestSetup129(void)
{
    int result = 0;
    Signature *sig;
    const char *value1_str = "<10";
    int value1 = 10;
    const char *value2_str = ">10";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_data->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x03) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (DetectIPProtoSetup(NULL, sig, value2_str) == 0)
        goto end;

    result = 1;

 end:
    SigFree(NULL, sig);
    return result;
}

static int DetectIPProtoTestSetup130(void)
{
    int result = 0;
    Signature *sig;
    const char *value1_str = "<10";
    const char *value2_str = ">10";
    int value2 = 10;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_data->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) == 0)
        goto end;
    for (i = 0; i < (value2 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0xF8) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }

    result = 1;

 end:
    SigFree(NULL, sig);
    return result;
}

static int DetectIPProtoTestSetup131(void)
{
    int result = 0;
    Signature *sig;
    const char *value1_str = "<10";
    int value1 = 10;
    const char *value2_str = "!10";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_data->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x03) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0x0)
            goto end;
    }

    result = 1;

 end:
    SigFree(NULL, sig);
    return result;
}

static int DetectIPProtoTestSetup132(void)
{
    int result = 0;
    Signature *sig;
    const char *value1_str = "<10";
    int value1 = 10;
    const char *value2_str = "!10";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_data->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x03) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0x0)
            goto end;
    }

    result = 1;

 end:
    SigFree(NULL, sig);
    return result;
}

static int DetectIPProtoTestSetup145(void)
{
    int result = 0;
    Signature *sig;
    const char *value1_str = "!4";
    const char *value2_str = ">8";
    const char *value3_str = "!10";
    const char *value4_str = "!14";
    const char *value5_str = "!27";
    const char *value6_str = "!29";
    const char *value7_str = "!30";
    const char *value8_str = "!34";
    const char *value9_str = "<36";
    const char *value10_str = "!38";
    int value10 = 38;

    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_data->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value5_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value8_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value10_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value6_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value9_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value4_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value7_str) != 0)
        goto end;
    if (sig->proto.proto[0] != 0) {
        goto end;
    }
    if (sig->proto.proto[1] != 0xBA) {
        goto end;
    }
    if (sig->proto.proto[2] != 0xFF) {
        goto end;
    }
    if (sig->proto.proto[3] != 0x97) {
        goto end;
    }
    if (sig->proto.proto[4] != 0x0B) {
        goto end;
    }
    for (i = (value10 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(NULL, sig);
    return result;
}

static int DetectIPProtoTestSig1(void)
{
    int result = 0;
    uint8_t *buf = (uint8_t *)
                    "GET /one/ HTTP/1.1\r\n"
                    "Host: one.example.org\r\n"
                    "\r\n";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket((uint8_t *)buf, buflen, IPPROTO_TCP);
    if (p == NULL)
        return 0;

    const char *sigs[4];
    sigs[0] = "alert ip any any -> any any "
        "(msg:\"Not tcp\"; ip_proto:!tcp; content:\"GET \"; sid:1;)";
    sigs[1] = "alert ip any any -> any any "
        "(msg:\"Less than 7\"; content:\"GET \"; ip_proto:<7; sid:2;)";
    sigs[2] = "alert ip any any -> any any "
        "(msg:\"Greater than 5\"; content:\"GET \"; ip_proto:>5; sid:3;)";
    sigs[3] = "alert ip any any -> any any "
        "(msg:\"Equals tcp\"; content:\"GET \"; ip_proto:tcp; sid:4;)";

    /* sids to match */
    uint32_t sid[4] = {1, 2, 3, 4};
    /* expected matches for each sid within this packet we are testing */
    uint32_t results[4] = {0, 1, 1, 1};

    /* remember that UTHGenericTest expect the first parameter
     * as an array of packet pointers. And also a bidimensional array of results
     * For example:
     * results[numpacket][position] should hold the number of times
     * that the sid at sid[position] matched that packet (should be always 1..)
     * But here we built it as unidimensional array
     */
    result = UTHGenericTest(&p, 1, sigs, sid, results, 4);

    UTHFreePacket(p);
    return result;
}

static int DetectIPProtoTestSig2(void)
{
    int result = 0;

    uint8_t raw_eth[] = {
        0x01, 0x00, 0x5e, 0x00, 0x00, 0x0d, 0x00, 0x26,
        0x88, 0x61, 0x3a, 0x80, 0x08, 0x00, 0x45, 0xc0,
        0x00, 0x36, 0xe4, 0xcd, 0x00, 0x00, 0x01, 0x67,
        0xc7, 0xab, 0xac, 0x1c, 0x7f, 0xfe, 0xe0, 0x00,
        0x00, 0x0d, 0x20, 0x00, 0x90, 0x20, 0x00, 0x01,
        0x00, 0x02, 0x00, 0x69, 0x00, 0x02, 0x00, 0x04,
        0x81, 0xf4, 0x07, 0xd0, 0x00, 0x13, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x14, 0x00, 0x04,
        0x4a, 0xea, 0x7a, 0x8e,
    };

    Packet *p = PacketGetFromAlloc();
    if (unlikely(p == NULL))
        return 0;

    DecodeThreadVars dtv;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;

    p->proto = 0;
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(th_v));

    FlowInitConfig(FLOW_QUIET);
    DecodeEthernet(&th_v, &dtv, p, raw_eth, sizeof(raw_eth));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert ip any any -> any any (msg:\"Check ipproto usage\"; "
                               "ip_proto:!103; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1) == 0) {
        result = 1;
        goto end;
    } else {
        result = 0;
    }

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    FlowShutdown();

    SCFree(p);
    return result;

end:
    if (de_ctx) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
    }

    if (det_ctx)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    if (de_ctx)
        DetectEngineCtxFree(de_ctx);

    FlowShutdown();
    SCFree(p);

    return result;
}

static int DetectIPProtoTestSig3(void)
{
    int result = 0;

    uint8_t raw_eth[] = {
        0x01, 0x00, 0x5e, 0x00, 0x00, 0x0d, 0x00, 0x26,
        0x88, 0x61, 0x3a, 0x80, 0x08, 0x00, 0x45, 0xc0,
        0x00, 0x36, 0xe4, 0xcd, 0x00, 0x00, 0x01, 0x67,
        0xc7, 0xab, 0xac, 0x1c, 0x7f, 0xfe, 0xe0, 0x00,
        0x00, 0x0d, 0x20, 0x00, 0x90, 0x20, 0x00, 0x01,
        0x00, 0x02, 0x00, 0x69, 0x00, 0x02, 0x00, 0x04,
        0x81, 0xf4, 0x07, 0xd0, 0x00, 0x13, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x01, 0x00, 0x14, 0x00, 0x04,
        0x4a, 0xea, 0x7a, 0x8e,
    };

    Packet *p = UTHBuildPacket((uint8_t *)"boom", 4, IPPROTO_TCP);
    if (p == NULL)
        return 0;

    DecodeThreadVars dtv;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;

    p->proto = 0;
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(th_v));

    FlowInitConfig(FLOW_QUIET);
    DecodeEthernet(&th_v, &dtv, p, raw_eth, sizeof(raw_eth));

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = mpm_default_matcher;
    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list = SigInit(de_ctx,
                               "alert ip any any -> any any (msg:\"Check ipproto usage\"; "
                               "ip_proto:103; sid:1;)");
    if (de_ctx->sig_list == NULL) {
        result = 0;
        goto end;
    }

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (!PacketAlertCheck(p, 1)) {
        result = 0;
        goto end;
    } else {
        result = 1;
    }

    SigGroupCleanup(de_ctx);
    SigCleanSignatures(de_ctx);

    DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    DetectEngineCtxFree(de_ctx);
    FlowShutdown();

    SCFree(p);
    return result;

end:
    if (de_ctx) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);
    }

    if (det_ctx)
        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
    if (de_ctx)
        DetectEngineCtxFree(de_ctx);

    FlowShutdown();
    SCFree(p);

    return result;
}

/**
 * \internal
 * \brief Register ip_proto tests.
 */
static void DetectIPProtoRegisterTests(void)
{
    UtRegisterTest("DetectIPProtoTestParse01", DetectIPProtoTestParse01);
    UtRegisterTest("DetectIPProtoTestParse02", DetectIPProtoTestParse02);
    UtRegisterTest("DetectIPProtoTestSetup01", DetectIPProtoTestSetup01);
    UtRegisterTest("DetectIPProtoTestSetup02", DetectIPProtoTestSetup02);
    UtRegisterTest("DetectIPProtoTestSetup03", DetectIPProtoTestSetup03);
    UtRegisterTest("DetectIPProtoTestSetup04", DetectIPProtoTestSetup04);
    UtRegisterTest("DetectIPProtoTestSetup05", DetectIPProtoTestSetup05);
    UtRegisterTest("DetectIPProtoTestSetup06", DetectIPProtoTestSetup06);
    UtRegisterTest("DetectIPProtoTestSetup07", DetectIPProtoTestSetup07);
    UtRegisterTest("DetectIPProtoTestSetup08", DetectIPProtoTestSetup08);
    UtRegisterTest("DetectIPProtoTestSetup09", DetectIPProtoTestSetup09);
    UtRegisterTest("DetectIPProtoTestSetup10", DetectIPProtoTestSetup10);
    UtRegisterTest("DetectIPProtoTestSetup11", DetectIPProtoTestSetup11);
    UtRegisterTest("DetectIPProtoTestSetup12", DetectIPProtoTestSetup12);
    UtRegisterTest("DetectIPProtoTestSetup13", DetectIPProtoTestSetup13);
    UtRegisterTest("DetectIPProtoTestSetup14", DetectIPProtoTestSetup14);
    UtRegisterTest("DetectIPProtoTestSetup15", DetectIPProtoTestSetup15);
    UtRegisterTest("DetectIPProtoTestSetup16", DetectIPProtoTestSetup16);
    UtRegisterTest("DetectIPProtoTestSetup17", DetectIPProtoTestSetup17);
    UtRegisterTest("DetectIPProtoTestSetup18", DetectIPProtoTestSetup18);
    UtRegisterTest("DetectIPProtoTestSetup19", DetectIPProtoTestSetup19);
    UtRegisterTest("DetectIPProtoTestSetup20", DetectIPProtoTestSetup20);
    UtRegisterTest("DetectIPProtoTestSetup21", DetectIPProtoTestSetup21);
    UtRegisterTest("DetectIPProtoTestSetup22", DetectIPProtoTestSetup22);
    UtRegisterTest("DetectIPProtoTestSetup23", DetectIPProtoTestSetup23);
    UtRegisterTest("DetectIPProtoTestSetup24", DetectIPProtoTestSetup24);
    UtRegisterTest("DetectIPProtoTestSetup33", DetectIPProtoTestSetup33);
    UtRegisterTest("DetectIPProtoTestSetup34", DetectIPProtoTestSetup34);
    UtRegisterTest("DetectIPProtoTestSetup36", DetectIPProtoTestSetup36);
    UtRegisterTest("DetectIPProtoTestSetup43", DetectIPProtoTestSetup43);
    UtRegisterTest("DetectIPProtoTestSetup44", DetectIPProtoTestSetup44);
    UtRegisterTest("DetectIPProtoTestSetup45", DetectIPProtoTestSetup45);
    UtRegisterTest("DetectIPProtoTestSetup56", DetectIPProtoTestSetup56);
    UtRegisterTest("DetectIPProtoTestSetup75", DetectIPProtoTestSetup75);
    UtRegisterTest("DetectIPProtoTestSetup76", DetectIPProtoTestSetup76);
    UtRegisterTest("DetectIPProtoTestSetup129", DetectIPProtoTestSetup129);
    UtRegisterTest("DetectIPProtoTestSetup130", DetectIPProtoTestSetup130);
    UtRegisterTest("DetectIPProtoTestSetup131", DetectIPProtoTestSetup131);
    UtRegisterTest("DetectIPProtoTestSetup132", DetectIPProtoTestSetup132);
    UtRegisterTest("DetectIPProtoTestSetup145", DetectIPProtoTestSetup145);

    UtRegisterTest("DetectIPProtoTestSig1", DetectIPProtoTestSig1);
    UtRegisterTest("DetectIPProtoTestSig2", DetectIPProtoTestSig2);
    UtRegisterTest("DetectIPProtoTestSig3", DetectIPProtoTestSig3);
}
#endif /* UNITTESTS */

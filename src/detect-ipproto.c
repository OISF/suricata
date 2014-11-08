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
 * \author Brian Rectanus <brectanu@gmail.com>
 *
 * Implements the ip_proto keyword
 */

#include "suricata-common.h"
#include "debug.h"
#include "decode.h"
#include "detect.h"

#include "detect-ipproto.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"

#include "detect-engine-siggroup.h"
#include "detect-engine-address.h"

#include "util-byte.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "util-debug.h"

/**
 * \brief Regex for parsing our options
 */
#define PARSE_REGEX  "^\\s*" \
                     "([!<>]?)" \
                     "\\s*([^\\s]+)" \
                     "\\s*$"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;

static int DetectIPProtoSetup(DetectEngineCtx *, Signature *, char *);
static DetectIPProtoData *DetectIPProtoParse(const char *);
static void DetectIPProtoRegisterTests(void);
static void DetectIPProtoFree(void *);

void DetectIPProtoRegister(void)
{
    const char *eb;
    int eo;
    int opts = 0;

    sigmatch_table[DETECT_IPPROTO].name = "ip_proto";
    sigmatch_table[DETECT_IPPROTO].desc = "match on the IP protocol in the packet-header";
    sigmatch_table[DETECT_IPPROTO].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Header_keywords#ip_proto";
    sigmatch_table[DETECT_IPPROTO].Match = NULL;
    sigmatch_table[DETECT_IPPROTO].Setup = DetectIPProtoSetup;
    sigmatch_table[DETECT_IPPROTO].Free  = DetectIPProtoFree;
    sigmatch_table[DETECT_IPPROTO].RegisterTests = DetectIPProtoRegisterTests;

    parse_regex = pcre_compile(PARSE_REGEX, opts, &eb, &eo, NULL);
    if (parse_regex == NULL) {
        SCLogError(SC_ERR_PCRE_COMPILE, "pcre compile of \"%s\" failed at "
                   "offset %" PRId32 ": %s", PARSE_REGEX, eo, eb);
        goto error;
    }

    parse_regex_study = pcre_study(parse_regex, 0, &eb);
    if (eb != NULL) {
        SCLogError(SC_ERR_PCRE_STUDY, "pcre study failed: %s", eb);
        goto error;
    }

    return;

error:
    if (parse_regex)
        pcre_free(parse_regex);
    if (parse_regex_study)
        pcre_free_study(parse_regex_study);
    return;
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
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];
    int i;
    const char *str_ptr;

    /* Execute the regex and populate args with captures. */
    ret = pcre_exec(parse_regex, parse_regex_study, optstr,
                    strlen(optstr), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret != 3) {
        SCLogError(SC_ERR_PCRE_MATCH, "pcre_exec parse error, ret"
                   "%" PRId32 ", string %s", ret, optstr);
        goto error;
    }

    for (i = 0; i < (ret - 1); i++) {
        res = pcre_get_substring((char *)optstr, ov, MAX_SUBSTRINGS,
                                 i + 1, &str_ptr);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
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
        struct protoent *pent = getprotobyname(args[1]);
        if (pent == NULL) {
            SCLogError(SC_ERR_INVALID_VALUE, "Malformed protocol name: %s",
                       str_ptr);
            goto error;
        }
        data->proto = (uint8_t)pent->p_proto;
    }
    else {
        if (ByteExtractStringUint8(&data->proto, 10, 0, args[1]) <= 0) {
            SCLogError(SC_ERR_INVALID_VALUE, "Malformed protocol number: %s",
                       str_ptr);
            goto error;
        }
    }

    for (i = 0; i < (ret - 1); i++){
        if (args[i] != NULL)
            SCFree(args[i]);
    }

    return data;

error:
    for (i = 0; i < (ret - 1) && i < 2; i++){
        if (args[i] != NULL)
            SCFree(args[i]);
    }
    if (data != NULL)
        SCFree(data);

    return NULL;
}

static int DetectIPProtoTypePresentForOP(Signature *s, uint8_t op)
{
    SigMatch *sm = s->sm_lists[DETECT_SM_LIST_MATCH];
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

/* Updated by AS.  Please do not remove this unused code.
 * Need it as we redo this code once we solve ipproto
 * multiple uses */
#if 0
static int DetectIPProtoQSortCompare(const void *a, const void *b)
{
    const uint8_t *one = a;
    const uint8_t *two = b;

    return ((int)*one - *two);
}
#endif

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
static int DetectIPProtoSetup(DetectEngineCtx *de_ctx, Signature *s, char *optstr)
{
    SigMatch *sm = NULL;
    DetectIPProtoData *data = NULL;
    int i;

    data = DetectIPProtoParse((const char *)optstr);
    if (data == NULL) {
        goto error;
    }

    /* Reset our "any" (or "ip") state: for ipv4, ipv6 and ip cases, the bitfield
     * s->proto.proto have all bit set to 1 to be able to match any protocols. ipproto
     * will refined the protocol list and thus it needs to reset the bitfield to zero
     * before setting the value specified by the ip_proto keyword.
     */
    if (s->proto.flags & (DETECT_PROTO_ANY | DETECT_PROTO_IPV6 | DETECT_PROTO_IPV4)) {
        s->proto.flags &= ~DETECT_PROTO_ANY;
        memset(s->proto.proto, 0x00, sizeof(s->proto.proto));
        s->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    } else {
        /* The ipproto engine has a relationship with the protocol that is
         * set after the action and also the app protocol(that can also be
         * set through the app-layer-protocol.
         * An ip_proto keyword can be used only with alert ip, which if
         * not true we error out on the sig.  And hence the init_flag to
         * indicate this. */
        if (!(s->init_flags & SIG_FLAG_INIT_FIRST_IPPROTO_SEEN)) {
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
                s->proto.proto[data->proto / 8] = 0xfe << (data->proto % 8);
                for (i = (data->proto / 8) + 1; i < (256 / 8); i++) {
                    s->proto.proto[i] = 0xff;
                }
            } else if (lt_set && !not_set) {
                SigMatch *temp_sm = s->sm_lists[DETECT_SM_LIST_MATCH];
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
                        /* Updated by AS.  Please do not remove this unused code.  Need it
                         * as we redo this code once we solve ipproto multiple uses */
#if 0
                        s->proto.proto[data->proto / 8] |= 0xfe << (data->proto % 8);
                        for (i = (data->proto / 8) + 1; i < (256 / 8); i++) {
                            s->proto.proto[i] = 0xff;
                        }
#endif
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
                SigMatch *temp_sm = s->sm_lists[DETECT_SM_LIST_MATCH];
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
                        /* Updated by AS.  Please do not remove this unused code.
                         * Need it as we redo this code once we solve ipproto
                         * multiple uses */
                        SCLogError(SC_ERR_INVALID_SIGNATURE, "can't have "
                                "both gt and lt ipprotos, with the lt being "
                                "lower than gt value");
                        goto error;
#if 0
                        s->proto.proto[data->proto / 8] |= 0xfe << (data->proto % 8);
                        for (i = (data->proto / 8) + 1; i < (256 / 8); i++) {
                            s->proto.proto[i] = 0xff;
                        }
                        temp_sm = s->sm_lists[DETECT_SM_LIST_MATCH];
                        uint8_t *not_protos = NULL;
                        int not_protos_len = 0;
                        while (temp_sm != NULL) {
                            if (temp_sm->type == DETECT_IPPROTO &&
                                    ((DetectIPProtoData *)temp_sm->ctx)->op == DETECT_IPPROTO_OP_NOT) {
                                DetectIPProtoData *data_temp = temp_sm->ctx;
                                not_protos = SCRealloc(not_protos,
                                        (not_protos_len + 1) * sizeof(uint8_t));
                                if (not_protos == NULL)
                                    goto error;
                                not_protos[not_protos_len] = data_temp->proto;
                                not_protos_len++;
                            }
                            temp_sm = temp_sm->next;
                        }
                        qsort(not_protos, not_protos_len, sizeof(uint8_t),
                                DetectIPProtoQSortCompare);
                        int j = 0;
                        while (j < not_protos_len) {
                            if (not_protos[j] < data->proto) {
                                ;
                            } else {
                                s->proto.proto[not_protos[j] / 8] &= ~(1 << (not_protos[j] % 8));
                            }
                            j++;
                        }
#endif
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
                s->proto.proto[data->proto / 8] = ~(0xff << (data->proto % 8));
            } else if (gt_set && !not_set) {
                SigMatch *temp_sm = s->sm_lists[DETECT_SM_LIST_MATCH];
                while (temp_sm != NULL) {
                    if (temp_sm->type == DETECT_IPPROTO) {
                        break;
                    }
                    temp_sm = temp_sm->next;
                }
                if (temp_sm != NULL) {
                  DetectIPProtoData *data_temp = (DetectIPProtoData *)temp_sm->ctx;
                    if (data_temp->proto >= data->proto) {
                        /* Updated by AS.  Please do not remove this unused code.
                         * Need it as we redo this code once we solve ipproto
                         * multiple uses */
                        SCLogError(SC_ERR_INVALID_SIGNATURE, "can't use a have "
                                "both gt and lt ipprotos, with the lt being "
                                "lower than gt value");
                        goto error;
#if 0
                        for (i = 0; i < (data->proto / 8); i++) {
                            s->proto.proto[i] = 0xff;
                        }
                        s->proto.proto[data->proto / 8] |= ~(0xff << (data->proto % 8));;
#endif
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
                SigMatch *temp_sm = s->sm_lists[DETECT_SM_LIST_MATCH];
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
                        /* Updated by AS.  Please do not remove this unused code.
                         * Need it as we redo this code once we solve ipproto
                         * multiple uses */
                        SCLogError(SC_ERR_INVALID_SIGNATURE, "can't have "
                                "both gt and lt ipprotos, with the lt being "
                                "lower than gt value");
                        goto error;
#if 0
                        for (i = 0; i < (data->proto / 8); i++) {
                            s->proto.proto[i] = 0xff;
                        }
                        s->proto.proto[data->proto / 8] |= ~(0xff << (data->proto % 8));
                        temp_sm = s->sm_lists[DETECT_SM_LIST_MATCH];
                        uint8_t *not_protos = NULL;
                        int not_protos_len = 0;
                        while (temp_sm != NULL) {
                            if (temp_sm->type == DETECT_IPPROTO &&
                                    ((DetectIPProtoData *)temp_sm->ctx)->op == DETECT_IPPROTO_OP_NOT) {
                                DetectIPProtoData *data_temp = temp_sm->ctx;
                                not_protos = SCRealloc(not_protos,
                                        (not_protos_len + 1) * sizeof(uint8_t));
                                if (not_protos == NULL)
                                    goto error;
                                not_protos[not_protos_len] = data_temp->proto;
                                not_protos_len++;
                            }
                            temp_sm = temp_sm->next;
                        }
                        qsort(not_protos, not_protos_len, sizeof(uint8_t),
                                DetectIPProtoQSortCompare);
                        int j = 0;
                        while (j < not_protos_len) {
                            if (not_protos[j] < data->proto) {
                                s->proto.proto[not_protos[j] / 8] &= ~(1 << (not_protos[j] % 8));
                            } else {
                                ;
                            }
                            j++;
                        }
#endif
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
                s->proto.proto[data->proto / 8] = ~(1 << (data->proto % 8));
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

    return -1;
}


void DetectIPProtoRemoveAllSMs(Signature *s)
{
    SigMatch *sm = s->sm_lists[DETECT_SM_LIST_MATCH];

    while (sm != NULL) {
        if (sm->type != DETECT_IPPROTO) {
            sm = sm->next;
            continue;
        }
        SigMatch *tmp_sm = sm->next;
        SigMatchRemoveSMFromList(s, sm, DETECT_SM_LIST_MATCH);
        SigMatchFree(sm);
        sm = tmp_sm;
    }

    return;
}

static void DetectIPProtoFree(void *ptr)
{
    DetectIPProtoData *data = (DetectIPProtoData *)ptr;
    if (data) {
        SCFree(data);
    }
}

/* UNITTESTS */
#ifdef UNITTESTS

#include "detect-engine.h"
#include "detect-parse.h"

/**
 * \test DetectIPProtoTestParse01 is a test for an invalid proto number
 */
static int DetectIPProtoTestParse01(void)
{
    int result = 0;
    DetectIPProtoData *data = NULL;
    data = DetectIPProtoParse("999");
    if (data == NULL) {
        result = 1;
    }

    if (data)
        SCFree(data);

    return result;
}

/**
 * \test DetectIPProtoTestParse02 is a test for an invalid proto name
 */
static int DetectIPProtoTestParse02(void)
{
    int result = 0;
    DetectIPProtoData *data = NULL;
    data = DetectIPProtoParse("foobarbooeek");
    if (data == NULL) {
        result = 1;
    }

    if (data)
        SCFree(data);

    return result;
}

/**
 * \test DetectIPProtoTestSetup01 is a test for a protocol number
 */
static int DetectIPProtoTestSetup01(void)
{
    int result = 0;
    Signature *sig;
    char *value_str = "14";
    int value = atoi(value_str);
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
    return result;
}

/**
 * \test DetectIPProtoTestSetup02 is a test for a protocol name
 */
static int DetectIPProtoTestSetup02(void)
{
    int result = 0;
    Signature *sig = NULL;
    char *value_str = "tcp";
    struct protoent *pent = getprotobyname(value_str);
    if (pent == NULL) {
        goto end;
    }
    uint8_t value = (uint8_t)pent->p_proto;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
        SigFree(sig);
    return result;
}

/**
 * \test DetectIPProtoTestSetup03 is a test for a < operator
 */
static int DetectIPProtoTestSetup03(void)
{
    int result = 0;
    Signature *sig;
    char *value_str = "<14";
    int value = 14;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
    return result;
}

/**
 * \test DetectIPProtoTestSetup04 is a test for a > operator
 */
static int DetectIPProtoTestSetup04(void)
{
    int result = 0;
    Signature *sig;
    char *value_str = ">14";
    int value = 14;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
    return result;
}

/**
 * \test DetectIPProtoTestSetup05 is a test for a ! operator
 */
static int DetectIPProtoTestSetup05(void)
{
    int result = 0;
    Signature *sig;
    char *value_str = "!14";
    int value = 14;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
    return result;
}

/**
 * \test Negative test.
 */
static int DetectIPProtoTestSetup06(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "14";
    char *value2_str = "15";

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != -1)
        goto end;

    result = 1;

 end:
    SigFree(sig);
    return result;
}

/**
 * \test Negative test.
 */
static int DetectIPProtoTestSetup07(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "14";
    char *value2_str = "<15";

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != -1)
        goto end;

    result = 1;

 end:
    SigFree(sig);
    return result;
}

/**
 * \test Negative test.
 */
static int DetectIPProtoTestSetup08(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "14";
    char *value2_str = ">15";

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != -1)
        goto end;

    result = 1;

 end:
    SigFree(sig);
    return result;
}

/**
 * \test Negative test.
 */
static int DetectIPProtoTestSetup09(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "14";
    char *value2_str = "!15";

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != -1)
        goto end;

    result = 1;

 end:
    SigFree(sig);
    return result;
}

/**
 * \test Negative test.
 */
static int DetectIPProtoTestSetup10(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">14";
    char *value2_str = "15";

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != -1)
        goto end;

    result = 1;

 end:
    SigFree(sig);
    return result;
}

/**
 * \test Negative test.
 */
static int DetectIPProtoTestSetup11(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<14";
    char *value2_str = "15";

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != -1)
        goto end;

    result = 1;

 end:
    SigFree(sig);
    return result;
}

/**
 * \test Negative test.
 */
static int DetectIPProtoTestSetup12(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!14";
    char *value2_str = "15";

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != -1)
        goto end;

    result = 1;

 end:
    SigFree(sig);
    return result;
}

/**
 * \test Negative test.
 */
static int DetectIPProtoTestSetup13(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">14";
    char *value2_str = ">15";

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != -1)
        goto end;

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup14(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<14";
    char *value2_str = "<15";

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != -1)
        goto end;

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup15(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<14";
    int value1 = 14;
    char *value2_str = ">34";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<14";
    int value1 = 14;
    char *value2_str = ">34";
    int value2 = 34;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x3F) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < (value2 / 8); i++) {
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
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup16(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<14";
    char *value2_str = ">34";
    int value2 = 34;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<14";
    int value1 = 14;
    char *value2_str = ">34";
    int value2 = 34;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x3F) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < (value2 / 8); i++) {
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
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup17(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    int value1 = 11;
    char *value2_str = ">13";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    int value1 = 11;
    char *value2_str = ">13";
    int value2 = 13;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0xC7) {
        goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0xC7) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup18(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    char *value2_str = ">13";
    int value2 = 13;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    int value1 = 11;
    char *value2_str = ">13";
    int value2 = 13;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0xC7) {
        goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0xC7) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup19(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    int value1 = 11;
    char *value2_str = "!13";
    char *value3_str = ">36";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    int value1 = 11;
    char *value2_str = "!13";
    char *value3_str = ">36";
    int value3 = 36;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x07) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < (value3 / 8); i++) {
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

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup20(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    int value1 = 11;
    char *value3_str = ">36";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    int value1 = 11;
    char *value2_str = "!13";
    char *value3_str = ">36";
    int value3 = 36;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
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
    for (i = (value1 / 8) + 1; i < (value3 / 8); i++) {
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

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup21(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    int value1 = 11;
    char *value2_str = "!13";
    char *value3_str = ">36";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    int value1 = 11;
    char *value2_str = "!13";
    char *value3_str = ">36";
    int value3 = 36;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x07) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < (value3 / 8); i++) {
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

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup22(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    char *value2_str = "!13";
    char *value3_str = ">36";
    int value3 = 36;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    int value1 = 11;
    char *value2_str = "!13";
    char *value3_str = ">36";
    int value3 = 36;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
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
    for (i = (value1 / 8) + 1; i < (value3 / 8); i++) {
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

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup23(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    char *value3_str = ">36";
    int value3 = 36;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    int value1 = 11;
    char *value2_str = "!13";
    char *value3_str = ">36";
    int value3 = 36;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
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
    for (i = (value1 / 8) + 1; i < (value3 / 8); i++) {
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

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup24(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    char *value2_str = "!13";
    char *value3_str = ">36";
    int value3 = 36;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    int value1 = 11;
    char *value2_str = "!13";
    char *value3_str = ">36";
    int value3 = 36;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
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
    for (i = (value1 / 8) + 1; i < (value3 / 8); i++) {
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

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup25(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    int value1 = 11;
    char *value2_str = "!18";
    char *value3_str = ">36";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    int value1 = 11;
    char *value2_str = "!18";
    char *value3_str = ">36";
    int value3 = 36;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x07) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < (value3 / 8); i++) {
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

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup26(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    int value1 = 11;
    char *value3_str = ">36";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
    return result;
#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    int value1 = 11;
    char *value2_str = "!18";
    char *value3_str = ">36";
    int value3 = 36;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
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
    for (i = (value1 / 8) + 1; i < (value3 / 8); i++) {
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

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup27(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    int value1 = 11;
    char *value2_str = "!18";
    char *value3_str = ">36";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
    return result;
#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    int value1 = 11;
    char *value2_str = "!18";
    char *value3_str = ">36";
    int value3 = 36;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x07) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < (value3 / 8); i++) {
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

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup28(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    char *value2_str = "!18";
    char *value3_str = ">36";
    int value3 = 36;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    int value1 = 11;
    char *value2_str = "!18";
    char *value3_str = ">36";
    int value3 = 36;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
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
    for (i = (value1 / 8) + 1; i < (value3 / 8); i++) {
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

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup29(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    char *value3_str = ">36";
    int value3 = 36;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    int value1 = 11;
    char *value2_str = "!18";
    char *value3_str = ">36";
    int value3 = 36;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
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
    for (i = (value1 / 8) + 1; i < (value3 / 8); i++) {
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

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup30(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    char *value2_str = "!18";
    char *value3_str = ">36";
    int value3 = 36;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    int value1 = 11;
    char *value2_str = "!18";
    char *value3_str = ">36";
    int value3 = 36;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
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
    for (i = (value1 / 8) + 1; i < (value3 / 8); i++) {
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

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup31(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    int value1 = 11;
    char *value2_str = "!34";
    char *value3_str = ">36";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    int value1 = 11;
    char *value2_str = "!34";
    char *value3_str = ">36";
    int value3 = 36;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x07) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < (value3 / 8); i++) {
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

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup32(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    int value1 = 11;
    char *value3_str = ">36";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    int value1 = 11;
    char *value2_str = "!34";
    char *value3_str = ">36";
    int value3 = 36;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
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
    for (i = (value1 / 8) + 1; i < (value3 / 8); i++) {
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

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup33(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    int value1 = 11;
    char *value2_str = "!34";
    char *value3_str = ">36";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    int value1 = 11;
    char *value2_str = "!34";
    char *value3_str = ">36";
    int value3 = 36;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x07) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < (value3 / 8); i++) {
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

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup34(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    int value1 = 11;
    char *value2_str = "!34";
    char *value3_str = ">36";
    int value3 = 36;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    int value1 = 11;
    char *value2_str = "!34";
    char *value3_str = ">36";
    int value3 = 36;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) == 0)
        goto end;

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup35(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    char *value3_str = ">36";
    int value3 = 36;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    int value1 = 11;
    char *value2_str = "!34";
    char *value3_str = ">36";
    int value3 = 36;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
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
    for (i = (value1 / 8) + 1; i < (value3 / 8); i++) {
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

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup36(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    char *value2_str = "!34";
    char *value3_str = ">36";
    int value3 = 36;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<11";
    int value1 = 11;
    char *value2_str = "!34";
    char *value3_str = ">36";
    int value3 = 36;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
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
    for (i = (value1 / 8) + 1; i < (value3 / 8); i++) {
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

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup37(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<10";
    int value1 = 10;
    char *value2_str = "!12";
    char *value3_str = ">14";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    for (i = (value1 / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0x0)
            goto end;
    }
    if (DetectIPProtoSetup(NULL, sig, value3_str) == 0)
        goto end;

    result = 1;

 end:
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<10";
    int value1 = 10;
    char *value2_str = "!12";
    char *value3_str = ">14";
    int value3 = 14;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x83) {
        goto end;
    }
    for (i = (value3 / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup38(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<10";
    int value1 = 10;
    char *value3_str = ">14";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    for (i = (value1 / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (DetectIPProtoSetup(NULL, sig, value3_str) == 0)
        goto end;

    result = 1;

 end:
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<10";
    int value1 = 10;
    char *value2_str = "!12";
    char *value3_str = ">14";
    int value3 = 14;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x83) {
        goto end;
    }
    for (i = (value3 / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup39(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<10";
    int value1 = 10;
    char *value2_str = "!12";
    char *value3_str = ">14";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    for (i = (value1 / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (DetectIPProtoSetup(NULL, sig, value3_str) == 0)
        goto end;

    result = 1;

 end:
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<10";
    int value1 = 10;
    char *value2_str = "!12";
    char *value3_str = ">14";
    int value3 = 14;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x83) {
        goto end;
    }
    for (i = (value3 / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup40(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<10";
    int value1 = 10;
    char *value2_str = "!12";
    char *value3_str = ">14";
    int value3 = 14;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    for (i = 0; i < (value3 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x80) {
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<10";
    int value1 = 10;
    char *value2_str = "!12";
    char *value3_str = ">14";
    int value3 = 14;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x83) {
        goto end;
    }
    for (i = (value3 / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup41(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<10";
    int value1 = 10;
    char *value3_str = ">14";
    int value3 = 14;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    for (i = 0; i < (value3 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x80) {
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<10";
    int value1 = 10;
    char *value2_str = "!12";
    char *value3_str = ">14";
    int value3 = 14;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x83) {
        goto end;
    }
    for (i = (value3 / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup42(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<10";
    int value1 = 10;
    char *value2_str = "!12";
    char *value3_str = ">14";
    int value3 = 14;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < (value3 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x80) {
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<10";
    int value1 = 10;
    char *value2_str = "!12";
    char *value3_str = ">14";
    int value3 = 14;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x83) {
        goto end;
    }
    for (i = (value3 / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup43(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!4";
    int value1 = 4;
    char *value2_str = "<13";
    int value2 = 13;
    char *value3_str = ">34";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "!4";
    int value1 = 4;
    char *value2_str = "<13";
    int value2 = 13;
    char *value3_str = ">34";
    int value3 = 34;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
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
    for (i = (value2 / 8) + 1; i < value3 / 8; i++) {
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

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup44(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!4";
    char *value2_str = "<13";
    char *value3_str = ">34";
    int value3 = 34;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "!4";
    int value1 = 4;
    char *value2_str = "<13";
    int value2 = 13;
    char *value3_str = ">34";
    int value3 = 34;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
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
    for (i = (value2 / 8) + 1; i < value3 / 8; i++) {
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

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup45(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!4";
    int value1 = 4;
    char *value2_str = "<13";
    int value2 = 13;
    char *value3_str = ">34";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "!4";
    int value1 = 4;
    char *value2_str = "<13";
    int value2 = 13;
    char *value3_str = ">34";
    int value3 = 34;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
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
    for (i = (value2 / 8) + 1; i < value3 / 8; i++) {
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

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup46(void)
{
    int result = 0;
    Signature *sig;
    char *value2_str = "<13";
    int value2 = 13;
    char *value3_str = ">34";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < (value2 / 8); i++) {
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "!4";
    int value1 = 4;
    char *value2_str = "<13";
    int value2 = 13;
    char *value3_str = ">34";
    int value3 = 34;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
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
    for (i = (value2 / 8) + 1; i < value3 / 8; i++) {
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

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup47(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!4";
    char *value2_str = "<13";
    char *value3_str = ">34";
    int value3 = 34;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "!4";
    int value1 = 4;
    char *value2_str = "<13";
    int value2 = 13;
    char *value3_str = ">34";
    int value3 = 34;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
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
    for (i = (value2 / 8) + 1; i < value3 / 8; i++) {
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

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup48(void)
{
    int result = 0;
    Signature *sig;
    char *value2_str = "<13";
    char *value3_str = ">34";
    int value3 = 34;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "!4";
    int value1 = 4;
    char *value2_str = "<13";
    int value2 = 13;
    char *value3_str = ">34";
    int value3 = 34;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
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
    for (i = (value2 / 8) + 1; i < value3 / 8; i++) {
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

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup49(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!11";
    int value1 = 11;
    char *value2_str = "<13";
    int value2 = 13;
    char *value3_str = ">34";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x17) {
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "!11";
    int value1 = 11;
    char *value2_str = "<13";
    int value2 = 13;
    char *value3_str = ">34";
    int value3 = 34;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x17) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < value3 / 8; i++) {
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

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup50(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!11";
    char *value2_str = "<13";
    char *value3_str = ">34";
    int value3 = 34;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    for (i = 0; i < value3 / 8; i++) {
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "!11";
    int value1 = 11;
    char *value2_str = "<13";
    int value2 = 13;
    char *value3_str = ">34";
    int value3 = 34;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x17) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < value3 / 8; i++) {
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

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup51(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!11";
    int value1 = 11;
    char *value2_str = "<13";
    int value2 = 13;
    char *value3_str = ">34";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x17) {
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "!11";
    int value1 = 11;
    char *value2_str = "<13";
    int value2 = 13;
    char *value3_str = ">34";
    int value3 = 34;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x17) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < value3 / 8; i++) {
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

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup52(void)
{
    int result = 0;
    Signature *sig;
    char *value2_str = "<13";
    int value2 = 13;
    char *value3_str = ">34";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < (value2 / 8); i++) {
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "!11";
    int value1 = 11;
    char *value2_str = "<13";
    int value2 = 13;
    char *value3_str = ">34";
    int value3 = 34;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x17) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < value3 / 8; i++) {
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

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup53(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!11";
    char *value2_str = "<13";
    char *value3_str = ">34";
    int value3 = 34;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    for (i = 0; i < value3 / 8; i++) {
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "!11";
    int value1 = 11;
    char *value2_str = "<13";
    int value2 = 13;
    char *value3_str = ">34";
    int value3 = 34;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x17) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < value3 / 8; i++) {
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

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup54(void)
{
    int result = 0;
    Signature *sig;
    char *value2_str = "<13";
    char *value3_str = ">34";
    int value3 = 34;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "!11";
    int value1 = 11;
    char *value2_str = "<13";
    int value2 = 13;
    char *value3_str = ">34";
    int value3 = 34;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x17) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < value3 / 8; i++) {
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

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup55(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<13";
    int value1 = 13;
    char *value2_str = ">34";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<13";
    int value1 = 13;
    char *value2_str = ">34";
    int value2 = 34;
    char *value3_str = "!37";
    int value3 = 37;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
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
    for (i = (value1 / 8) + 1; i < value2 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0xD8) {
        goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup56(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<13";
    int value1 = 13;
    char *value2_str = ">34";
    char *value3_str = "!37";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<13";
    int value1 = 13;
    char *value2_str = ">34";
    int value2 = 34;
    char *value3_str = "!37";
    int value3 = 37;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x1F) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < value2 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0xD8) {
        goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup57(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<13";
    char *value2_str = ">34";
    int value2 = 34;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < value2 / 8; i++) {
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
    if (DetectIPProtoSetup(NULL, sig, value1_str) == 0)
        goto end;

    result = 1;

 end:
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<13";
    int value1 = 13;
    char *value2_str = ">34";
    int value2 = 34;
    char *value3_str = "!37";
    int value3 = 37;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
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
    for (i = (value1 / 8) + 1; i < value2 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0xD8) {
        goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup58(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<13";
    char *value2_str = ">34";
    int value2 = 34;
    char *value3_str = "!37";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    for (i = 0; i < value2 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0xD8) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (DetectIPProtoSetup(NULL, sig, value1_str) == 0)
        goto end;

    result = 1;

 end:
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<13";
    int value1 = 13;
    char *value2_str = ">34";
    int value2 = 34;
    char *value3_str = "!37";
    int value3 = 37;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x1F) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < value2 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0xD8) {
        goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup59(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<13";
    int value1 = 13;
    char *value2_str = ">34";
    char *value3_str = "!37";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<13";
    int value1 = 13;
    char *value2_str = ">34";
    int value2 = 34;
    char *value3_str = "!37";
    int value3 = 37;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x1F) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < value2 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0xD8) {
        goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup60(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<13";
    char *value2_str = ">34";
    int value2 = 34;
    char *value3_str = "!37";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < value2 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0xD8) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (DetectIPProtoSetup(NULL, sig, value1_str) == 0)
        goto end;

    result = 1;

 end:
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<13";
    int value1 = 13;
    char *value2_str = ">34";
    int value2 = 34;
    char *value3_str = "!37";
    int value3 = 37;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x1F) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < value2 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0xD8) {
        goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup61(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<13";
    int value1 = 13;
    char *value2_str = ">34";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<13";
    int value1 = 13;
    char *value2_str = ">34";
    int value2 = 34;
    char *value3_str = "!44";
    int value3 = 44;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
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
    for (i = (value1 / 8) + 1; i < value2 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0xF8) {
        goto end;
    }
    if (sig->proto.proto[value3 / 8] != 0xEF) {
        goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup62(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<13";
    int value1 = 13;
    char *value2_str = ">34";
    char *value3_str = "!44";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<13";
    int value1 = 13;
    char *value2_str = ">34";
    int value2 = 34;
    char *value3_str = "!44";
    int value3 = 44;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x1F) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < value2 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0xF8) {
        goto end;
    }
    if (sig->proto.proto[value3 / 8] != 0xEF) {
        goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup63(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<13";
    char *value2_str = ">34";
    int value2 = 34;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < value2 / 8; i++) {
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
    if (DetectIPProtoSetup(NULL, sig, value1_str) == 0)
        goto end;

    result = 1;

 end:
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<13";
    int value1 = 13;
    char *value2_str = ">34";
    int value2 = 34;
    char *value3_str = "!44";
    int value3 = 44;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
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
    for (i = (value1 / 8) + 1; i < value2 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0xF8) {
        goto end;
    }
    if (sig->proto.proto[value3 / 8] != 0xEF) {
        goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup64(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<13";
    char *value2_str = ">34";
    int value2 = 34;
    char *value3_str = "!44";
    int value3 = 44;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    for (i = 0; i < value2 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0xF8) {
        goto end;
    }
    if (sig->proto.proto[value3 / 8] != 0xEF) {
        goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (DetectIPProtoSetup(NULL, sig, value1_str) == 0)
        goto end;

    result = 1;

 end:
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<13";
    int value1 = 13;
    char *value2_str = ">34";
    int value2 = 34;
    char *value3_str = "!44";
    int value3 = 44;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x1F) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < value2 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0xF8) {
        goto end;
    }
    if (sig->proto.proto[value3 / 8] != 0xEF) {
        goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup65(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<13";
    int value1 = 13;
    char *value2_str = ">34";
    char *value3_str = "!44";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
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
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<13";
    int value1 = 13;
    char *value2_str = ">34";
    int value2 = 34;
    char *value3_str = "!44";
    int value3 = 44;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x1F) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < value2 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0xF8) {
        goto end;
    }
    if (sig->proto.proto[value3 / 8] != 0xEF) {
        goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup66(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<13";
    char *value2_str = ">34";
    int value2 = 34;
    char *value3_str = "!44";
    int value3 = 44;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < value2 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0xF8) {
        goto end;
    }
    if (sig->proto.proto[value3 / 8] != 0xEF) {
        goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (DetectIPProtoSetup(NULL, sig, value1_str) == 0)
        goto end;

    result = 1;

 end:
    SigFree(sig);
    return result;

#if 0
    int result = 0;
    Signature *sig;
    char *value1_str = "<13";
    int value1 = 13;
    char *value2_str = ">34";
    int value2 = 34;
    char *value3_str = "!44";
    int value3 = 44;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x1F) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < value2 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0xF8) {
        goto end;
    }
    if (sig->proto.proto[value3 / 8] != 0xEF) {
        goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
#endif
}

static int DetectIPProtoTestSetup67(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">14";
    int value1 = 14;
    char *value2_str = "<34";
    int value2 = 34;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x80) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < (value2 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0x03) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0x0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup68(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">14";
    int value1 = 14;
    char *value2_str = "<34";
    int value2 = 34;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x80) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < (value2 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0x03) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0x0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup69(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">10";
    int value1 = 10;
    char *value2_str = "<14";
    int value2 = 14;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x38) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0x0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup70(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">10";
    int value1 = 10;
    char *value2_str = "<14";
    int value2 = 14;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x38) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0x0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup71(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">10";
    int value1 = 10;
    char *value2_str = "!14";
    int value2 = 14;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0xB8) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup72(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">10";
    int value1 = 10;
    char *value2_str = "!14";
    int value2 = 14;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0xB8) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup73(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">10";
    int value1 = 10;
    char *value2_str = "!34";
    int value2 = 34;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0xF8) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < (value2 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0xFB) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup74(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">10";
    int value1 = 10;
    char *value2_str = "!34";
    int value2 = 34;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0xF8) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < (value2 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0xFB) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup75(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!8";
    char *value2_str = ">10";
    int value2 = 10;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup76(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!8";
    char *value2_str = ">10";
    int value2 = 10;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup77(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!4";
    char *value2_str = ">10";
    int value2 = 10;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup78(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!4";
    char *value2_str = ">10";
    int value2 = 10;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup79(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!4";
    int value1 = 4;
    char *value2_str = "<10";
    int value2 = 10;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (sig->proto.proto[value1 / 8] != 0xEF) {
        goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0x03) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup80(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!4";
    int value1 = 4;
    char *value2_str = "<10";
    int value2 = 10;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (sig->proto.proto[value1 / 8] != 0xEF) {
        goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0x03) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup81(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!9";
    int value1 = 9;
    char *value2_str = "<13";
    int value2 = 13;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x1D) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup82(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!9";
    int value1 = 9;
    char *value2_str = "<13";
    int value2 = 13;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0x1D) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < (256 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup83(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<10";
    int value1 = 10;
    char *value2_str = "!13";
    int value2 = 13;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    for (i = (value2 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup84(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<10";
    int value1 = 10;
    char *value2_str = "!13";
    int value2 = 13;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    for (i = (value2 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup85(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<10";
    int value1 = 10;
    char *value2_str = "!35";
    int value2 = 35;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    for (i = (value2 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup86(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<10";
    int value1 = 10;
    char *value2_str = "!35";
    int value2 = 35;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    for (i = (value2 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup87(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!4";
    char *value2_str = ">10";
    int value2 = 10;
    char *value3_str = "<35";
    int value3 = 35;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    for (i = 0; i < (value2 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0xF8) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < (value3 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value3 / 8] != 0x07) {
        goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0x0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup88(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!4";
    char *value2_str = ">10";
    int value2 = 10;
    char *value3_str = "<35";
    int value3 = 35;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
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
    for (i = (value2 / 8) + 1; i < (value3 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value3 / 8] != 0x07) {
        goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0x0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup89(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!4";
    char *value2_str = ">10";
    int value2 = 10;
    char *value3_str = "<35";
    int value3 = 35;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    for (i = 0; i < (value2 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0xF8) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < (value3 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value3 / 8] != 0x07) {
        goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0x0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup90(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!4";
    char *value2_str = ">10";
    int value2 = 10;
    char *value3_str = "<35";
    int value3 = 35;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
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
    for (i = (value2 / 8) + 1; i < (value3 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value3 / 8] != 0x07) {
        goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0x0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup91(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!4";
    char *value2_str = ">10";
    int value2 = 10;
    char *value3_str = "<35";
    int value3 = 35;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
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
    for (i = (value2 / 8) + 1; i < (value3 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value3 / 8] != 0x07) {
        goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0x0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup92(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!4";
    char *value2_str = ">10";
    int value2 = 10;
    char *value3_str = "<35";
    int value3 = 35;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
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
    for (i = (value2 / 8) + 1; i < (value3 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value3 / 8] != 0x07) {
        goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0x0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup93(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!9";
    char *value2_str = ">12";
    int value2 = 12;
    char *value3_str = "<35";
    int value3 = 35;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    for (i = 0; i < (value2 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0xE0) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < (value3 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup94(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!9";
    char *value2_str = ">12";
    int value2 = 12;
    char *value3_str = "<35";
    int value3 = 35;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < (value2 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0xE0) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < (value3 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup95(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!9";
    char *value2_str = ">12";
    int value2 = 12;
    char *value3_str = "<35";
    int value3 = 35;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    for (i = 0; i < (value2 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0xE0) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < (value3 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup96(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!9";
    char *value2_str = ">12";
    int value2 = 12;
    char *value3_str = "<35";
    int value3 = 35;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    for (i = 0; i < (value2 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0xE0) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < (value3 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup97(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!9";
    char *value2_str = ">12";
    int value2 = 12;
    char *value3_str = "<35";
    int value3 = 35;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < (value2 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0xE0) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < (value3 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup98(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!9";
    char *value2_str = ">12";
    int value2 = 12;
    char *value3_str = "<35";
    int value3 = 35;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    for (i = 0; i < (value2 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0xE0) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < (value3 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup99(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">10";
    int value1 = 10;
    char *value2_str = "!13";
    int value2 = 13;
    char *value3_str = "<35";
    int value3 = 35;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0xD8) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < (value3 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup100(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">10";
    int value1 = 10;
    char *value2_str = "!13";
    int value2 = 13;
    char *value3_str = "<35";
    int value3 = 35;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0xD8) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < (value3 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup101(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">10";
    int value1 = 10;
    char *value2_str = "!13";
    int value2 = 13;
    char *value3_str = "<35";
    int value3 = 35;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0xD8) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < (value3 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup102(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">10";
    int value1 = 10;
    char *value2_str = "!13";
    int value2 = 13;
    char *value3_str = "<35";
    int value3 = 35;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0xD8) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < (value3 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup103(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">10";
    int value1 = 10;
    char *value2_str = "!13";
    int value2 = 13;
    char *value3_str = "<35";
    int value3 = 35;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0xD8) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < (value3 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup104(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">10";
    int value1 = 10;
    char *value2_str = "!13";
    int value2 = 13;
    char *value3_str = "<35";
    int value3 = 35;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0xD8) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < (value3 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup105(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">10";
    int value1 = 10;
    char *value2_str = "!18";
    int value2 = 18;
    char *value3_str = "<35";
    int value3 = 35;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0xF8) {
        goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0xFB) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < (value3 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup106(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">10";
    int value1 = 10;
    char *value2_str = "!18";
    int value2 = 18;
    char *value3_str = "<35";
    int value3 = 35;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0xF8) {
        goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0xFB) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < (value3 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup107(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">10";
    int value1 = 10;
    char *value2_str = "!18";
    int value2 = 18;
    char *value3_str = "<35";
    int value3 = 35;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0xF8) {
        goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0xFB) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < (value3 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup108(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">10";
    int value1 = 10;
    char *value2_str = "!18";
    int value2 = 18;
    char *value3_str = "<35";
    int value3 = 35;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0xF8) {
        goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0xFB) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < (value3 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup109(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">10";
    int value1 = 10;
    char *value2_str = "!18";
    int value2 = 18;
    char *value3_str = "<35";
    int value3 = 35;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0xF8) {
        goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0xFB) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < (value3 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup110(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">10";
    int value1 = 10;
    char *value2_str = "!18";
    int value2 = 18;
    char *value3_str = "<35";
    int value3 = 35;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0xF8) {
        goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0xFB) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < (value3 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup111(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">10";
    int value1 = 10;
    char *value2_str = "!33";
    char *value3_str = "<35";
    int value3 = 35;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0xF8) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < (value3 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value3 / 8] != 0x05) {
        goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup112(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">10";
    int value1 = 10;
    char *value2_str = "!33";
    char *value3_str = "<35";
    int value3 = 35;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0xF8) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < (value3 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value3 / 8] != 0x05) {
        goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup113(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">10";
    int value1 = 10;
    char *value2_str = "!33";
    char *value3_str = "<35";
    int value3 = 35;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0xF8) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < (value3 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value3 / 8] != 0x05) {
        goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup114(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">10";
    int value1 = 10;
    char *value2_str = "!33";
    char *value3_str = "<35";
    int value3 = 35;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0xF8) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < (value3 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value3 / 8] != 0x05) {
        goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup115(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">10";
    int value1 = 10;
    char *value2_str = "!33";
    char *value3_str = "<35";
    int value3 = 35;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0xF8) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < (value3 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value3 / 8] != 0x05) {
        goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup116(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">10";
    int value1 = 10;
    char *value2_str = "!33";
    char *value3_str = "<35";
    int value3 = 35;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0xF8) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < (value3 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value3 / 8] != 0x05) {
        goto end;
    }
    for (i = (value3 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup117(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">10";
    int value1 = 10;
    char *value2_str = "<34";
    int value2 = 34;
    char *value3_str = "!38";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0xF8) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < (value2 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0x03) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0x0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup118(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">10";
    int value1 = 10;
    char *value2_str = "<34";
    int value2 = 34;
    char *value3_str = "!38";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0xF8) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < (value2 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0x03) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0x0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup119(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">10";
    int value1 = 10;
    char *value2_str = "<34";
    int value2 = 34;
    char *value3_str = "!38";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0xF8) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < (value2 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0x03) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0x0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup120(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">10";
    int value1 = 10;
    char *value2_str = "<34";
    int value2 = 34;
    char *value3_str = "!38";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0xF8) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < (value2 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0x03) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0x0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup121(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">10";
    int value1 = 10;
    char *value2_str = "<34";
    int value2 = 34;
    char *value3_str = "!38";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0xF8) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < (value2 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0x03) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0x0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup122(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">10";
    int value1 = 10;
    char *value2_str = "<34";
    int value2 = 34;
    char *value3_str = "!38";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0xF8) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < (value2 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0x03) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0x0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup123(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">10";
    int value1 = 10;
    char *value2_str = "<34";
    int value2 = 34;
    char *value3_str = "!45";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0xF8) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < (value2 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0x03) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0x0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup124(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">10";
    int value1 = 10;
    char *value2_str = "<34";
    int value2 = 34;
    char *value3_str = "!45";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0xF8) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < (value2 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0x03) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0x0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup125(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">10";
    int value1 = 10;
    char *value2_str = "<34";
    int value2 = 34;
    char *value3_str = "!45";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0xF8) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < (value2 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0x03) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0x0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup126(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">10";
    int value1 = 10;
    char *value2_str = "<34";
    int value2 = 34;
    char *value3_str = "!45";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0xF8) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < (value2 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0x03) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0x0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup127(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">10";
    int value1 = 10;
    char *value2_str = "<34";
    int value2 = 34;
    char *value3_str = "!45";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0xF8) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < (value2 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0x03) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0x0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup128(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">10";
    int value1 = 10;
    char *value2_str = "<34";
    int value2 = 34;
    char *value3_str = "!45";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0xF8) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < (value2 / 8); i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }
    if (sig->proto.proto[value2 / 8] != 0x03) {
        goto end;
    }
    for (i = (value2 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0x0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup129(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<10";
    int value1 = 10;
    char *value2_str = ">10";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup130(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<10";
    char *value2_str = ">10";
    int value2 = 10;
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup131(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<10";
    int value1 = 10;
    char *value2_str = "!10";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup132(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "<10";
    int value1 = 10;
    char *value2_str = "!10";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup133(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">10";
    int value1 = 10;
    char *value2_str = "!10";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0x0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0xF8) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}


static int DetectIPProtoTestSetup134(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = ">10";
    int value1 = 10;
    char *value2_str = "!10";
    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    for (i = 0; i < (value1 / 8); i++) {
        if (sig->proto.proto[i] != 0x0)
            goto end;
    }
    if (sig->proto.proto[value1 / 8] != 0xF8) {
        goto end;
    }
    for (i = (value1 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0xFF)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup135(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!4";
    char *value2_str = ">8";
    char *value3_str = "!27";
    char *value4_str = "!29";
    char *value5_str = "!30";
    char *value6_str = "!34";
    char *value7_str = "<36";
    char *value8_str = "!38";
    int value8 = 38;

    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value4_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value5_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value6_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value7_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value8_str) != 0)
        goto end;
    if (sig->proto.proto[0] != 0) {
        goto end;
    }
    if (sig->proto.proto[1] != 0xFE) {
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
    for (i = (value8 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup136(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!4";
    char *value2_str = ">8";
    char *value3_str = "!27";
    char *value4_str = "!29";
    char *value5_str = "!30";
    char *value6_str = "!34";
    char *value7_str = "<36";
    char *value8_str = "!38";
    int value8 = 38;

    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value8_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value7_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value6_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value5_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value4_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (sig->proto.proto[0] != 0) {
        goto end;
    }
    if (sig->proto.proto[1] != 0xFE) {
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
    for (i = (value8 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup137(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!4";
    char *value2_str = ">8";
    char *value3_str = "!27";
    char *value4_str = "!29";
    char *value5_str = "!30";
    char *value6_str = "!34";
    char *value7_str = "<36";
    char *value8_str = "!38";
    int value8 = 38;

    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value5_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value7_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value8_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value4_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value6_str) != 0)
        goto end;
    if (sig->proto.proto[0] != 0) {
        goto end;
    }
    if (sig->proto.proto[1] != 0xFE) {
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
    for (i = (value8 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup138(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!4";
    char *value2_str = ">8";
    char *value3_str = "!27";
    char *value4_str = "!29";
    char *value5_str = "!30";
    char *value6_str = "!34";
    char *value7_str = "<36";
    char *value8_str = "!38";
    int value8 = 38;

    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value7_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value4_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value8_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value6_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value5_str) != 0)
        goto end;
    if (sig->proto.proto[0] != 0) {
        goto end;
    }
    if (sig->proto.proto[1] != 0xFE) {
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
    for (i = (value8 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup139(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!4";
    char *value2_str = ">8";
    char *value3_str = "!27";
    char *value4_str = "!29";
    char *value5_str = "!30";
    char *value6_str = "!34";
    char *value7_str = "<36";
    char *value8_str = "!38";
    int value8 = 38;

    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value7_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value5_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value8_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value6_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value4_str) != 0)
        goto end;
    if (sig->proto.proto[0] != 0) {
        goto end;
    }
    if (sig->proto.proto[1] != 0xFE) {
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
    for (i = (value8 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup140(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!4";
    char *value2_str = ">8";
    char *value3_str = "!27";
    char *value4_str = "!29";
    char *value5_str = "!30";
    char *value6_str = "!34";
    char *value7_str = "<36";
    char *value8_str = "!38";
    int value8 = 38;

    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value4_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value8_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value6_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value7_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value5_str) != 0)
        goto end;
    if (sig->proto.proto[0] != 0) {
        goto end;
    }
    if (sig->proto.proto[1] != 0xFE) {
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
    for (i = (value8 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup141(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!4";
    char *value2_str = ">8";
    char *value3_str = "!27";
    char *value4_str = "!29";
    char *value5_str = "!30";
    char *value6_str = "!34";
    char *value7_str = "<36";
    char *value8_str = "!38";
    int value8 = 38;

    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value6_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value8_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value7_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value5_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value4_str) != 0)
        goto end;
    if (sig->proto.proto[0] != 0) {
        goto end;
    }
    if (sig->proto.proto[1] != 0xFE) {
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
    for (i = (value8 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup142(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!4";
    char *value2_str = ">8";
    char *value3_str = "!27";
    char *value4_str = "!29";
    char *value5_str = "!30";
    char *value6_str = "!34";
    char *value7_str = "<36";
    char *value8_str = "!38";
    int value8 = 38;

    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value4_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value8_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value5_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value7_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value6_str) != 0)
        goto end;
    if (sig->proto.proto[0] != 0) {
        goto end;
    }
    if (sig->proto.proto[1] != 0xFE) {
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
    for (i = (value8 / 8) + 1; i < 256 / 8; i++) {
        if (sig->proto.proto[i] != 0)
            goto end;
    }

    result = 1;

 end:
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup143(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!4";
    char *value2_str = ">8";
    char *value3_str = "!10";
    char *value4_str = "!14";
    char *value5_str = "!27";
    char *value6_str = "!29";
    char *value7_str = "!30";
    char *value8_str = "!34";
    char *value9_str = "<36";
    char *value10_str = "!38";
    int value10 = 38;

    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value4_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value5_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value6_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value7_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value8_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value9_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value10_str) != 0)
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
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup144(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!4";
    char *value2_str = ">8";
    char *value3_str = "!10";
    char *value4_str = "!14";
    char *value5_str = "!27";
    char *value6_str = "!29";
    char *value7_str = "!30";
    char *value8_str = "!34";
    char *value9_str = "<36";
    char *value10_str = "!38";
    int value10 = 38;

    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
    sig->proto.flags |= DETECT_PROTO_ANY;
    if (DetectIPProtoSetup(NULL, sig, value10_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value9_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value8_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value7_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value6_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value5_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value4_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value3_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value2_str) != 0)
        goto end;
    if (DetectIPProtoSetup(NULL, sig, value1_str) != 0)
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
    SigFree(sig);
    return result;
}

static int DetectIPProtoTestSetup145(void)
{
    int result = 0;
    Signature *sig;
    char *value1_str = "!4";
    char *value2_str = ">8";
    char *value3_str = "!10";
    char *value4_str = "!14";
    char *value5_str = "!27";
    char *value6_str = "!29";
    char *value7_str = "!30";
    char *value8_str = "!34";
    char *value9_str = "<36";
    char *value10_str = "!38";
    int value10 = 38;

    int i;

    if ((sig = SigAlloc()) == NULL)
        goto end;

    sig->init_flags |= SIG_FLAG_INIT_FIRST_IPPROTO_SEEN;
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
    SigFree(sig);
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
        goto end;

    char *sigs[4];
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
end:
    DetectSigGroupPrintMemory();
    DetectAddressPrintMemory();
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

    Packet *p = SCMalloc(SIZE_OF_PACKET);
    if (unlikely(p == NULL))
        return 0;
    memset(p, 0, SIZE_OF_PACKET);

    DecodeThreadVars dtv;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;

    p->proto = 0;
    memset(&dtv, 0, sizeof(DecodeThreadVars));
    memset(&th_v, 0, sizeof(th_v));

    FlowInitConfig(FLOW_QUIET);
    DecodeEthernet(&th_v, &dtv, p, raw_eth, sizeof(raw_eth), NULL);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = DEFAULT_MPM;
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
    DecodeEthernet(&th_v, &dtv, p, raw_eth, sizeof(raw_eth), NULL);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL) {
        goto end;
    }

    de_ctx->mpm_matcher = DEFAULT_MPM;
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

#endif /* UNITTESTS */

/**
 * \internal
 * \brief Register ip_proto tests.
 */
static void DetectIPProtoRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectIPProtoTestParse01", DetectIPProtoTestParse01, 1);
    UtRegisterTest("DetectIPProtoTestParse02", DetectIPProtoTestParse02, 1);
    UtRegisterTest("DetectIPProtoTestSetup01", DetectIPProtoTestSetup01, 1);
    UtRegisterTest("DetectIPProtoTestSetup02", DetectIPProtoTestSetup02, 1);
    UtRegisterTest("DetectIPProtoTestSetup03", DetectIPProtoTestSetup03, 1);
    UtRegisterTest("DetectIPProtoTestSetup04", DetectIPProtoTestSetup04, 1);
    UtRegisterTest("DetectIPProtoTestSetup05", DetectIPProtoTestSetup05, 1);
    UtRegisterTest("DetectIPProtoTestSetup06", DetectIPProtoTestSetup06, 1);
    UtRegisterTest("DetectIPProtoTestSetup07", DetectIPProtoTestSetup07, 1);
    UtRegisterTest("DetectIPProtoTestSetup08", DetectIPProtoTestSetup08, 1);
    UtRegisterTest("DetectIPProtoTestSetup09", DetectIPProtoTestSetup09, 1);
    UtRegisterTest("DetectIPProtoTestSetup10", DetectIPProtoTestSetup10, 1);
    UtRegisterTest("DetectIPProtoTestSetup11", DetectIPProtoTestSetup11, 1);
    UtRegisterTest("DetectIPProtoTestSetup12", DetectIPProtoTestSetup12, 1);
    UtRegisterTest("DetectIPProtoTestSetup13", DetectIPProtoTestSetup13, 1);
    UtRegisterTest("DetectIPProtoTestSetup14", DetectIPProtoTestSetup14, 1);
    UtRegisterTest("DetectIPProtoTestSetup15", DetectIPProtoTestSetup15, 1);
    UtRegisterTest("DetectIPProtoTestSetup16", DetectIPProtoTestSetup16, 1);
    UtRegisterTest("DetectIPProtoTestSetup17", DetectIPProtoTestSetup17, 1);
    UtRegisterTest("DetectIPProtoTestSetup18", DetectIPProtoTestSetup18, 1);
    UtRegisterTest("DetectIPProtoTestSetup19", DetectIPProtoTestSetup19, 1);
    UtRegisterTest("DetectIPProtoTestSetup20", DetectIPProtoTestSetup20, 1);
    UtRegisterTest("DetectIPProtoTestSetup21", DetectIPProtoTestSetup21, 1);
    UtRegisterTest("DetectIPProtoTestSetup22", DetectIPProtoTestSetup22, 1);
    UtRegisterTest("DetectIPProtoTestSetup23", DetectIPProtoTestSetup23, 1);
    UtRegisterTest("DetectIPProtoTestSetup24", DetectIPProtoTestSetup24, 1);
    UtRegisterTest("DetectIPProtoTestSetup25", DetectIPProtoTestSetup25, 1);
    UtRegisterTest("DetectIPProtoTestSetup26", DetectIPProtoTestSetup26, 1);
    UtRegisterTest("DetectIPProtoTestSetup27", DetectIPProtoTestSetup27, 1);
    UtRegisterTest("DetectIPProtoTestSetup28", DetectIPProtoTestSetup28, 1);
    UtRegisterTest("DetectIPProtoTestSetup29", DetectIPProtoTestSetup29, 1);
    UtRegisterTest("DetectIPProtoTestSetup30", DetectIPProtoTestSetup30, 1);
    UtRegisterTest("DetectIPProtoTestSetup31", DetectIPProtoTestSetup31, 1);
    UtRegisterTest("DetectIPProtoTestSetup32", DetectIPProtoTestSetup32, 1);
    UtRegisterTest("DetectIPProtoTestSetup33", DetectIPProtoTestSetup33, 1);
    UtRegisterTest("DetectIPProtoTestSetup34", DetectIPProtoTestSetup34, 1);
    UtRegisterTest("DetectIPProtoTestSetup35", DetectIPProtoTestSetup35, 1);
    UtRegisterTest("DetectIPProtoTestSetup36", DetectIPProtoTestSetup36, 1);
    UtRegisterTest("DetectIPProtoTestSetup37", DetectIPProtoTestSetup37, 1);
    UtRegisterTest("DetectIPProtoTestSetup38", DetectIPProtoTestSetup38, 1);
    UtRegisterTest("DetectIPProtoTestSetup39", DetectIPProtoTestSetup39, 1);
    UtRegisterTest("DetectIPProtoTestSetup40", DetectIPProtoTestSetup40, 1);
    UtRegisterTest("DetectIPProtoTestSetup41", DetectIPProtoTestSetup41, 1);
    UtRegisterTest("DetectIPProtoTestSetup42", DetectIPProtoTestSetup42, 1);
    UtRegisterTest("DetectIPProtoTestSetup43", DetectIPProtoTestSetup43, 1);
    UtRegisterTest("DetectIPProtoTestSetup44", DetectIPProtoTestSetup44, 1);
    UtRegisterTest("DetectIPProtoTestSetup45", DetectIPProtoTestSetup45, 1);
    UtRegisterTest("DetectIPProtoTestSetup46", DetectIPProtoTestSetup46, 1);
    UtRegisterTest("DetectIPProtoTestSetup47", DetectIPProtoTestSetup47, 1);
    UtRegisterTest("DetectIPProtoTestSetup48", DetectIPProtoTestSetup48, 1);
    UtRegisterTest("DetectIPProtoTestSetup49", DetectIPProtoTestSetup49, 1);
    UtRegisterTest("DetectIPProtoTestSetup50", DetectIPProtoTestSetup50, 1);
    UtRegisterTest("DetectIPProtoTestSetup51", DetectIPProtoTestSetup51, 1);
    UtRegisterTest("DetectIPProtoTestSetup52", DetectIPProtoTestSetup52, 1);
    UtRegisterTest("DetectIPProtoTestSetup53", DetectIPProtoTestSetup53, 1);
    UtRegisterTest("DetectIPProtoTestSetup54", DetectIPProtoTestSetup54, 1);
    UtRegisterTest("DetectIPProtoTestSetup55", DetectIPProtoTestSetup55, 1);
    UtRegisterTest("DetectIPProtoTestSetup56", DetectIPProtoTestSetup56, 1);
    UtRegisterTest("DetectIPProtoTestSetup57", DetectIPProtoTestSetup57, 1);
    UtRegisterTest("DetectIPProtoTestSetup58", DetectIPProtoTestSetup58, 1);
    UtRegisterTest("DetectIPProtoTestSetup59", DetectIPProtoTestSetup59, 1);
    UtRegisterTest("DetectIPProtoTestSetup60", DetectIPProtoTestSetup60, 1);
    UtRegisterTest("DetectIPProtoTestSetup61", DetectIPProtoTestSetup61, 1);
    UtRegisterTest("DetectIPProtoTestSetup62", DetectIPProtoTestSetup62, 1);
    UtRegisterTest("DetectIPProtoTestSetup63", DetectIPProtoTestSetup63, 1);
    UtRegisterTest("DetectIPProtoTestSetup64", DetectIPProtoTestSetup64, 1);
    UtRegisterTest("DetectIPProtoTestSetup65", DetectIPProtoTestSetup65, 1);
    UtRegisterTest("DetectIPProtoTestSetup66", DetectIPProtoTestSetup66, 1);
    UtRegisterTest("DetectIPProtoTestSetup67", DetectIPProtoTestSetup67, 1);
    UtRegisterTest("DetectIPProtoTestSetup68", DetectIPProtoTestSetup68, 1);
    UtRegisterTest("DetectIPProtoTestSetup69", DetectIPProtoTestSetup69, 1);
    UtRegisterTest("DetectIPProtoTestSetup70", DetectIPProtoTestSetup70, 1);
    UtRegisterTest("DetectIPProtoTestSetup71", DetectIPProtoTestSetup71, 1);
    UtRegisterTest("DetectIPProtoTestSetup72", DetectIPProtoTestSetup72, 1);
    UtRegisterTest("DetectIPProtoTestSetup73", DetectIPProtoTestSetup73, 1);
    UtRegisterTest("DetectIPProtoTestSetup74", DetectIPProtoTestSetup74, 1);
    UtRegisterTest("DetectIPProtoTestSetup75", DetectIPProtoTestSetup75, 1);
    UtRegisterTest("DetectIPProtoTestSetup76", DetectIPProtoTestSetup76, 1);
    UtRegisterTest("DetectIPProtoTestSetup77", DetectIPProtoTestSetup77, 1);
    UtRegisterTest("DetectIPProtoTestSetup78", DetectIPProtoTestSetup78, 1);
    UtRegisterTest("DetectIPProtoTestSetup79", DetectIPProtoTestSetup79, 1);
    UtRegisterTest("DetectIPProtoTestSetup80", DetectIPProtoTestSetup80, 1);
    UtRegisterTest("DetectIPProtoTestSetup81", DetectIPProtoTestSetup81, 1);
    UtRegisterTest("DetectIPProtoTestSetup82", DetectIPProtoTestSetup82, 1);
    UtRegisterTest("DetectIPProtoTestSetup83", DetectIPProtoTestSetup83, 1);
    UtRegisterTest("DetectIPProtoTestSetup84", DetectIPProtoTestSetup84, 1);
    UtRegisterTest("DetectIPProtoTestSetup85", DetectIPProtoTestSetup85, 1);
    UtRegisterTest("DetectIPProtoTestSetup86", DetectIPProtoTestSetup86, 1);
    UtRegisterTest("DetectIPProtoTestSetup87", DetectIPProtoTestSetup87, 1);
    UtRegisterTest("DetectIPProtoTestSetup88", DetectIPProtoTestSetup88, 1);
    UtRegisterTest("DetectIPProtoTestSetup89", DetectIPProtoTestSetup89, 1);
    UtRegisterTest("DetectIPProtoTestSetup90", DetectIPProtoTestSetup90, 1);
    UtRegisterTest("DetectIPProtoTestSetup91", DetectIPProtoTestSetup91, 1);
    UtRegisterTest("DetectIPProtoTestSetup92", DetectIPProtoTestSetup92, 1);
    UtRegisterTest("DetectIPProtoTestSetup93", DetectIPProtoTestSetup93, 1);
    UtRegisterTest("DetectIPProtoTestSetup94", DetectIPProtoTestSetup94, 1);
    UtRegisterTest("DetectIPProtoTestSetup95", DetectIPProtoTestSetup95, 1);
    UtRegisterTest("DetectIPProtoTestSetup96", DetectIPProtoTestSetup96, 1);
    UtRegisterTest("DetectIPProtoTestSetup97", DetectIPProtoTestSetup97, 1);
    UtRegisterTest("DetectIPProtoTestSetup98", DetectIPProtoTestSetup98, 1);
    UtRegisterTest("DetectIPProtoTestSetup99", DetectIPProtoTestSetup99, 1);
    UtRegisterTest("DetectIPProtoTestSetup100", DetectIPProtoTestSetup100, 1);
    UtRegisterTest("DetectIPProtoTestSetup101", DetectIPProtoTestSetup101, 1);
    UtRegisterTest("DetectIPProtoTestSetup102", DetectIPProtoTestSetup102, 1);
    UtRegisterTest("DetectIPProtoTestSetup103", DetectIPProtoTestSetup103, 1);
    UtRegisterTest("DetectIPProtoTestSetup104", DetectIPProtoTestSetup104, 1);
    UtRegisterTest("DetectIPProtoTestSetup105", DetectIPProtoTestSetup105, 1);
    UtRegisterTest("DetectIPProtoTestSetup106", DetectIPProtoTestSetup106, 1);
    UtRegisterTest("DetectIPProtoTestSetup107", DetectIPProtoTestSetup107, 1);
    UtRegisterTest("DetectIPProtoTestSetup108", DetectIPProtoTestSetup108, 1);
    UtRegisterTest("DetectIPProtoTestSetup109", DetectIPProtoTestSetup109, 1);
    UtRegisterTest("DetectIPProtoTestSetup110", DetectIPProtoTestSetup110, 1);
    UtRegisterTest("DetectIPProtoTestSetup111", DetectIPProtoTestSetup111, 1);
    UtRegisterTest("DetectIPProtoTestSetup112", DetectIPProtoTestSetup112, 1);
    UtRegisterTest("DetectIPProtoTestSetup113", DetectIPProtoTestSetup113, 1);
    UtRegisterTest("DetectIPProtoTestSetup114", DetectIPProtoTestSetup114, 1);
    UtRegisterTest("DetectIPProtoTestSetup115", DetectIPProtoTestSetup115, 1);
    UtRegisterTest("DetectIPProtoTestSetup116", DetectIPProtoTestSetup116, 1);
    UtRegisterTest("DetectIPProtoTestSetup117", DetectIPProtoTestSetup117, 1);
    UtRegisterTest("DetectIPProtoTestSetup118", DetectIPProtoTestSetup118, 1);
    UtRegisterTest("DetectIPProtoTestSetup119", DetectIPProtoTestSetup119, 1);
    UtRegisterTest("DetectIPProtoTestSetup120", DetectIPProtoTestSetup120, 1);
    UtRegisterTest("DetectIPProtoTestSetup121", DetectIPProtoTestSetup121, 1);
    UtRegisterTest("DetectIPProtoTestSetup122", DetectIPProtoTestSetup122, 1);
    UtRegisterTest("DetectIPProtoTestSetup123", DetectIPProtoTestSetup123, 1);
    UtRegisterTest("DetectIPProtoTestSetup124", DetectIPProtoTestSetup124, 1);
    UtRegisterTest("DetectIPProtoTestSetup125", DetectIPProtoTestSetup125, 1);
    UtRegisterTest("DetectIPProtoTestSetup126", DetectIPProtoTestSetup126, 1);
    UtRegisterTest("DetectIPProtoTestSetup127", DetectIPProtoTestSetup127, 1);
    UtRegisterTest("DetectIPProtoTestSetup128", DetectIPProtoTestSetup128, 1);
    UtRegisterTest("DetectIPProtoTestSetup129", DetectIPProtoTestSetup129, 1);
    UtRegisterTest("DetectIPProtoTestSetup130", DetectIPProtoTestSetup130, 1);
    UtRegisterTest("DetectIPProtoTestSetup131", DetectIPProtoTestSetup131, 1);
    UtRegisterTest("DetectIPProtoTestSetup132", DetectIPProtoTestSetup132, 1);
    UtRegisterTest("DetectIPProtoTestSetup133", DetectIPProtoTestSetup133, 1);
    UtRegisterTest("DetectIPProtoTestSetup134", DetectIPProtoTestSetup134, 1);
    UtRegisterTest("DetectIPProtoTestSetup135", DetectIPProtoTestSetup135, 1);
    UtRegisterTest("DetectIPProtoTestSetup136", DetectIPProtoTestSetup136, 1);
    UtRegisterTest("DetectIPProtoTestSetup137", DetectIPProtoTestSetup137, 1);
    UtRegisterTest("DetectIPProtoTestSetup138", DetectIPProtoTestSetup138, 1);
    UtRegisterTest("DetectIPProtoTestSetup139", DetectIPProtoTestSetup139, 1);
    UtRegisterTest("DetectIPProtoTestSetup140", DetectIPProtoTestSetup140, 1);
    UtRegisterTest("DetectIPProtoTestSetup141", DetectIPProtoTestSetup141, 1);
    UtRegisterTest("DetectIPProtoTestSetup142", DetectIPProtoTestSetup142, 1);
    UtRegisterTest("DetectIPProtoTestSetup143", DetectIPProtoTestSetup143, 1);
    UtRegisterTest("DetectIPProtoTestSetup144", DetectIPProtoTestSetup144, 1);
    UtRegisterTest("DetectIPProtoTestSetup145", DetectIPProtoTestSetup145, 1);

    UtRegisterTest("DetectIPProtoTestSig1", DetectIPProtoTestSig1, 1);
    UtRegisterTest("DetectIPProtoTestSig2", DetectIPProtoTestSig2, 1);
    UtRegisterTest("DetectIPProtoTestSig3", DetectIPProtoTestSig3, 1);
#endif /* UNITTESTS */
}

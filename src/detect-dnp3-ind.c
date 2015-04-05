/* Copyright (C) 2015 Open Information Security Foundation
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

#include "suricata-common.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-dnp3.h"

/**
 * Map of indicators names (Snort compatible) to flags for specifying
 * indicators by name.
 */
typedef struct DNP3IndicatorMapping_ {
    char name[22];
    uint16_t flags;
} DNP3IndicatorMapping;

DNP3IndicatorMapping DNP3IndicatorsMap[] = {
    {"device_restart",        0x8000},
    {"device_trouble",        0x4000},
    {"local_control",         0x2000},
    {"need_time",             0x1000},
    {"class_3_events",        0x0800},
    {"class_2_events",        0x0400},
    {"class_1_events",        0x0200},
    {"all_stations",          0x0100},

    {"reserved_1",            0x0080},
    {"reserved_2",            0x0040},
    {"config_corrupt",        0x0020},
    {"already_executing",     0x0010},
    {"event_buffer_overflow", 0x0008},
    {"parameter_error",       0x0004},
    {"object_unknown",        0x0002},
    {"no_func_code_support",  0x0001},
};

static void DetectDNP3IndRegisterTests(void);

static int DetectDNP3IndParseAsInteger(char *str, uint16_t *flags)
{
    unsigned long val;
    char *ep;

    errno = 0;
    val = strtoul(str, &ep, 0);
    if (str[0] == '\0' || *ep != '\0') {
        goto error;
    }
    if (errno == ERANGE && val == ULONG_MAX) {
        goto error;
    }

    *flags = (uint16_t)val;

    return 1;
error:
    return 0;
}

static char *TrimString(char *str)
{
    char *end = str + strlen(str) - 1;
    while (isspace(*str)) {
        str++;
    }
    while (end > str && isspace(*end)) {
        end--;
    }
    *(end + 1) = '\0';
    return str;
}

static int DetectDNP3IndParseByName(char *str, uint16_t *flags)
{
    char tmp[strlen(str) + 1];
    char *p, *last;

    strncpy(tmp, str, strlen(str) + 1);

    for ((p = strtok_r(tmp, ",", &last)); p; (p = strtok_r(NULL, ",", &last))) {
        p = TrimString(p);
        int found = 0;
        for (size_t i = 0;
             i < sizeof(DNP3IndicatorsMap) / sizeof(DNP3IndicatorMapping);
             i++) {
            if (strcasecmp(p, DNP3IndicatorsMap[i].name) == 0) {
                *flags |= DNP3IndicatorsMap[i].flags;
                found = 1;
                break;
            }
        }

        if (!found) {
            SCLogError(SC_ERR_INVALID_SIGNATURE,
                "Bad argument \"%s\" supplied to dnp3.ind keyword.", p);
            return 0;
        }
    }

    return 1;
}

static int DetectDNP3IndParse(char *str, uint16_t *flags)
{
    *flags = 0;

    /* First attempt to parse as an integer. */
    if (DetectDNP3IndParseAsInteger(str, flags)) {
        return 1;
    }

    /* Parse by name. */
    if (DetectDNP3IndParseByName(str, flags)) {
        return 1;
    }

    return 0;
}

static int DetectDNP3IndSetup(DetectEngineCtx *de_ctx, Signature *s, char *str)
{
    SCEnter();
    DetectDNP3 *detect = NULL;
    SigMatch *sm = NULL;
    uint16_t flags;

    if (!DetectDNP3IndParse(str, &flags)) {
        SCLogError(SC_ERR_INVALID_SIGNATURE,
            "Invalid argument \"%s\" supplied to dnp3.ind keyword.", str);
        return -1;
    }

    detect = SCCalloc(1, sizeof(DetectDNP3));
    if (unlikely(detect == NULL)) {
        goto error;
    }
    detect->type = DNP3_DETECT_INTERNAL_INDICATOR;
    detect->ind_flags = flags;

    sm = SigMatchAlloc();
    if (sm == NULL) {
        goto error;
    }

    sm->type = DETECT_AL_DNP3FUNC;
    sm->ctx = (void *)detect;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_DNP3_MATCH);
    s->alproto = ALPROTO_DNP3;
    s->flags |= SIG_FLAG_STATE_MATCH;

    SCReturnInt(0);
error:
    if (detect != NULL) {
        SCFree(detect);
    }
    if (sm != NULL) {
        SCFree(sm);
    }
    SCReturnInt(-1);
}

static void DetectDNP3IndFree(void *ptr)
{
    SCEnter();
    if (ptr != NULL) {
        SCFree(ptr);
    }
    SCReturn;
}

void DetectDNP3IndRegister(void)
{
    SCEnter();

    sigmatch_table[DETECT_AL_DNP3IND].name          = "dnp3.ind";
    sigmatch_table[DETECT_AL_DNP3IND].alias         = "dnp3_inc";
    sigmatch_table[DETECT_AL_DNP3IND].Match         = NULL;
    sigmatch_table[DETECT_AL_DNP3IND].AppLayerMatch = NULL;
    sigmatch_table[DETECT_AL_DNP3IND].alproto       = ALPROTO_DNP3;
    sigmatch_table[DETECT_AL_DNP3IND].Setup         = DetectDNP3IndSetup;
    sigmatch_table[DETECT_AL_DNP3IND].Free          = DetectDNP3IndFree;
    sigmatch_table[DETECT_AL_DNP3IND].RegisterTests =
        DetectDNP3IndRegisterTests;

    SCReturn;
}

#ifdef UNITTESTS

#include "detect-engine.h"
#include "util-unittest.h"

#define FAIL_IF(expr) do {                                      \
        if (expr) {                                             \
            printf("Failed at %s:%d\n", __FILE__, __LINE__);    \
            goto fail;                                          \
        }                                                       \
    } while (0);

static int DetectDNP3IndTestParseAsInteger(void)
{
    uint16_t flags = 0;
    int result = 0;

    FAIL_IF(!DetectDNP3IndParse("0", &flags));
    FAIL_IF(flags != 0);
    FAIL_IF(!DetectDNP3IndParse("1", &flags));
    FAIL_IF(flags != 0x0001);

    FAIL_IF(!DetectDNP3IndParse("0x0", &flags));
    FAIL_IF(flags != 0);
    FAIL_IF(!DetectDNP3IndParse("0x0000", &flags));
    FAIL_IF(flags != 0);
    FAIL_IF(!DetectDNP3IndParse("0x0001", &flags));
    FAIL_IF(flags != 0x0001);

    FAIL_IF(!DetectDNP3IndParse("0x8421", &flags));
    FAIL_IF(flags != 0x8421);

    FAIL_IF(DetectDNP3IndParse("a", &flags));

    result = 1;
fail:
    return result;
}

static int DetectDNP3IndTestParseByName(void)
{
    int result = 0;
    uint16_t flags = 0;

    FAIL_IF(!DetectDNP3IndParse("all_stations", &flags));
    FAIL_IF(!(flags & 0x0100));
    FAIL_IF(!DetectDNP3IndParse("class_1_events , class_2_events", &flags));
    FAIL_IF(!(flags & 0x0200));
    FAIL_IF(!(flags & 0x0400));
    FAIL_IF((flags & 0xf9ff));

    FAIL_IF(DetectDNP3IndParse("something", &flags));

    result = 1;
fail:
    return result;
}

#endif

static void DetectDNP3IndRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectDNP3IndTestParseAsInteger",
        DetectDNP3IndTestParseAsInteger, 1);
    UtRegisterTest("DetectDNP3IndTestParseByName", DetectDNP3IndTestParseByName,
        1);
#endif
}

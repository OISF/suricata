/* Copyright (C) 2020 Open Information Security Foundation
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
 * \author Sascha Steinbiss <sascha@steinbiss.name>
 */

#include "suricata-common.h"
#include "conf.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-content-inspection.h"
#include "detect-mqtt-connect-flags.h"
#include "util-unittest.h"

#include "rust.h"

#define PARSE_REGEX "(?: *,?!?(?:username|password|will|will_retain|clean_session))+"
static DetectParseRegex parse_regex;

static int mqtt_connect_flags_id = 0;

static int DetectMQTTConnectFlagsMatch(DetectEngineThreadCtx *det_ctx,
                               Flow *f, uint8_t flags, void *state,
                               void *txv, const Signature *s,
                               const SigMatchCtx *ctx);
static int DetectMQTTConnectFlagsSetup (DetectEngineCtx *, Signature *, const char *);
void MQTTConnectFlagsRegisterTests(void);
void DetectMQTTConnectFlagsFree(DetectEngineCtx *de_ctx, void *);

typedef struct DetectMQTTConnectFlagsData_ {
    MQTTFlagState username,
                  password,
                  will,
                  will_retain,
                  clean_session;
} DetectMQTTConnectFlagsData;

/**
 * \brief Registration function for mqtt.connect.flags: keyword
 */
void DetectMQTTConnectFlagsRegister (void)
{
    sigmatch_table[DETECT_AL_MQTT_CONNECT_FLAGS].name = "mqtt.connect.flags";
    sigmatch_table[DETECT_AL_MQTT_CONNECT_FLAGS].desc = "match MQTT CONNECT variable header flags";
    sigmatch_table[DETECT_AL_MQTT_CONNECT_FLAGS].url = "/rules/mqtt-keywords.html#mqtt-connect-flags";
    sigmatch_table[DETECT_AL_MQTT_CONNECT_FLAGS].AppLayerTxMatch = DetectMQTTConnectFlagsMatch;
    sigmatch_table[DETECT_AL_MQTT_CONNECT_FLAGS].Setup = DetectMQTTConnectFlagsSetup;
    sigmatch_table[DETECT_AL_MQTT_CONNECT_FLAGS].Free  = DetectMQTTConnectFlagsFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_MQTT_CONNECT_FLAGS].RegisterTests = MQTTConnectFlagsRegisterTests;
#endif

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);

    DetectAppLayerInspectEngineRegister2("mqtt.connect.flags", ALPROTO_MQTT, SIG_FLAG_TOSERVER, 1,
            DetectEngineInspectGenericList, NULL);

    mqtt_connect_flags_id = DetectBufferTypeGetByName("mqtt.connect.flags");
}

/**
 * \internal
 * \brief Function to match variable header flags of an MQTT CONNECT Tx
 *
 * \param det_ctx Pointer to the pattern matcher thread.
 * \param f       Pointer to the current flow.
 * \param flags   Flags.
 * \param state   App layer state.
 * \param txv     Pointer to the transaction.
 * \param s       Pointer to the Signature.
 * \param ctx     Pointer to the sigmatch that we will cast into DetectMQTTConnectFlagsData.
 *
 * \retval 0 no match.
 * \retval 1 match.
 */
static int DetectMQTTConnectFlagsMatch(DetectEngineThreadCtx *det_ctx,
                               Flow *f, uint8_t flags, void *state,
                               void *txv, const Signature *s,
                               const SigMatchCtx *ctx)
{
    const DetectMQTTConnectFlagsData *de = (const DetectMQTTConnectFlagsData *)ctx;

    if (!de)
        return 0;

    return rs_mqtt_tx_has_connect_flags(txv, de->username, de->password, de->will,
                                        de->will_retain, de->clean_session);
   }

/**
 * \internal
 * \brief This function is used to parse options passed via mqtt.connect.flags: keyword
 *
 * \param rawstr Pointer to the user provided options
 *
 * \retval de pointer to DetectMQTTConnectFlagsData on success
 * \retval NULL on failure
 */
static DetectMQTTConnectFlagsData *DetectMQTTConnectFlagsParse(const char *rawstr)
{
    DetectMQTTConnectFlagsData *de = NULL;
    int ret = 0;

    ret = DetectParsePcreExec(&parse_regex, rawstr, 0, 0);
    if (ret < 1) {
        SCLogError(SC_ERR_PCRE_MATCH, "invalid flag definition: %s", rawstr);
        return NULL;
    }

    de = SCCalloc(1, sizeof(DetectMQTTConnectFlagsData));
    if (unlikely(de == NULL))
        return NULL;
    de->username = de->password = de->will = MQTT_DONT_CARE;
    de->will_retain = de->clean_session = MQTT_DONT_CARE;

    char copy[strlen(rawstr)+1];
    strlcpy(copy, rawstr, sizeof(copy));
    char *xsaveptr = NULL;
    char *flagv = strtok_r(copy, ",", &xsaveptr);
    while (flagv != NULL) {
        while (*flagv != '\0' && isblank(*flagv)) {
            flagv++;
        }
        if (strlen(flagv) < 2) {
            SCLogError(SC_ERR_UNKNOWN_VALUE, "malformed flag value: %s", flagv);
            goto error;
        }  else {
            int offset = 0;
            MQTTFlagState fs_to_set = MQTT_MUST_BE_SET;
            if (flagv[0] == '!') {
                /* negated flag */
                offset = 1;  /* skip negation operator during comparison */
                fs_to_set = MQTT_CANT_BE_SET;
            }
            if (strcmp(flagv+offset, "username") == 0) {
                if (de->username != MQTT_DONT_CARE) {
                    SCLogError(SC_EINVAL, "duplicate flag definition: %s", flagv);
                    goto error;
                }
                de->username = fs_to_set;
            } else if (strcmp(flagv+offset, "password") == 0) {
                if (de->password != MQTT_DONT_CARE) {
                    SCLogError(SC_EINVAL, "duplicate flag definition: %s", flagv);
                    goto error;
                }
                de->password = fs_to_set;
            } else if (strcmp(flagv+offset, "will") == 0) {
                if (de->will != MQTT_DONT_CARE) {
                    SCLogError(SC_EINVAL, "duplicate flag definition: %s", flagv);
                    goto error;
                }
                de->will = fs_to_set;
            } else if (strcmp(flagv+offset, "will_retain") == 0) {
                if (de->will_retain != MQTT_DONT_CARE) {
                    SCLogError(SC_EINVAL, "duplicate flag definition: %s", flagv);
                    goto error;
                }
                de->will_retain = fs_to_set;
            } else if (strcmp(flagv+offset, "clean_session") == 0) {
                if (de->clean_session != MQTT_DONT_CARE) {
                    SCLogError(SC_EINVAL, "duplicate flag definition: %s", flagv);
                    goto error;
                }
                de->clean_session = fs_to_set;
            } else {
                SCLogError(SC_ERR_UNKNOWN_VALUE, "invalid flag definition: %s", flagv);
                goto error;
            }
        }
        flagv = strtok_r(NULL, ",", &xsaveptr);
    }

    return de;

error:
    /* de can't be NULL here */
    SCFree(de);
    return NULL;
}

/**
 * \internal
 * \brief this function is used to add the parsed type query into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param rawstr pointer to the user provided options
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectMQTTConnectFlagsSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectMQTTConnectFlagsData *de = NULL;
    SigMatch *sm = NULL;

    if (DetectSignatureSetAppProto(s, ALPROTO_MQTT) < 0)
        return -1;

    de = DetectMQTTConnectFlagsParse(rawstr);
    if (de == NULL)
        goto error;

    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_AL_MQTT_CONNECT_FLAGS;
    sm->ctx = (SigMatchCtx *)de;

    SigMatchAppendSMToList(s, sm, mqtt_connect_flags_id);

    return 0;

error:
    if (de != NULL)
        SCFree(de);
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

/**
 * \internal
 * \brief this function will free memory associated with DetectMQTTConnectFlagsData
 *
 * \param de pointer to DetectMQTTConnectFlagsData
 */
void DetectMQTTConnectFlagsFree(DetectEngineCtx *de_ctx, void *de_ptr)
{
    if (de_ptr != NULL)
        SCFree(de_ptr);
}

/*
 * ONLY TESTS BELOW THIS COMMENT
 */

#ifdef UNITTESTS
/**
 * \test MQTTConnectFlagsTestParse01 is a test for a valid value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int MQTTConnectFlagsTestParse01 (void)
{
    DetectMQTTConnectFlagsData *de = NULL;
    de = DetectMQTTConnectFlagsParse("username");
    FAIL_IF_NULL(de);
    DetectMQTTConnectFlagsFree(NULL, de);

    de = DetectMQTTConnectFlagsParse("username,password,will,will_retain,clean_session");
    FAIL_IF_NULL(de);
    DetectMQTTConnectFlagsFree(NULL, de);

    de = DetectMQTTConnectFlagsParse("!username,!password,!will,!will_retain,!clean_session");
    FAIL_IF_NULL(de);
    DetectMQTTConnectFlagsFree(NULL, de);

    de = DetectMQTTConnectFlagsParse("   username,password");
    FAIL_IF_NULL(de);
    DetectMQTTConnectFlagsFree(NULL, de);

    PASS;
}

/**
 * \test MQTTConnectFlagsTestParse02 is a test for an invalid value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int MQTTConnectFlagsTestParse02 (void)
{
    DetectMQTTConnectFlagsData *de = NULL;
    de = DetectMQTTConnectFlagsParse("foobar");
    if (de) {
        DetectMQTTConnectFlagsFree(NULL, de);
        FAIL;
    }

    PASS;
}

/**
 * \test MQTTConnectFlagsTestParse03 is a test for an invalid value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int MQTTConnectFlagsTestParse03 (void)
{
    DetectMQTTConnectFlagsData *de = NULL;
    de = DetectMQTTConnectFlagsParse("will,!");
    if (de) {
        DetectMQTTConnectFlagsFree(NULL, de);
        FAIL;
    }

    PASS;
}

/**
 * \test MQTTConnectFlagsTestParse04 is a test for an invalid value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int MQTTConnectFlagsTestParse04 (void)
{
    DetectMQTTConnectFlagsData *de = NULL;
    de = DetectMQTTConnectFlagsParse("");
    if (de) {
        DetectMQTTConnectFlagsFree(NULL, de);
        FAIL;
    }

    PASS;
}

/**
 * \test MQTTConnectFlagsTestParse05 is a test for an invalid value
 *
 *  \retval 1 on success
 *  \retval 0 on failure
 */
static int MQTTConnectFlagsTestParse05 (void)
{
    DetectMQTTConnectFlagsData *de = NULL;
    de = DetectMQTTConnectFlagsParse("username, username");
    if (de) {
        DetectMQTTConnectFlagsFree(NULL, de);
        FAIL;
    }
    de = DetectMQTTConnectFlagsParse("!username, username");
    if (de) {
        DetectMQTTConnectFlagsFree(NULL, de);
        FAIL;
    }
    de = DetectMQTTConnectFlagsParse("!username,password,!password");
    if (de) {
        DetectMQTTConnectFlagsFree(NULL, de);
        FAIL;
    }
    de = DetectMQTTConnectFlagsParse("will, username,password,   !will, will");
    if (de) {
        DetectMQTTConnectFlagsFree(NULL, de);
        FAIL;
    }

    PASS;
}


#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for MQTTConnectFlags
 */
void MQTTConnectFlagsRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("MQTTConnectFlagsTestParse01", MQTTConnectFlagsTestParse01);
    UtRegisterTest("MQTTConnectFlagsTestParse02", MQTTConnectFlagsTestParse02);
    UtRegisterTest("MQTTConnectFlagsTestParse03", MQTTConnectFlagsTestParse03);
    UtRegisterTest("MQTTConnectFlagsTestParse04", MQTTConnectFlagsTestParse04);
    UtRegisterTest("MQTTConnectFlagsTestParse05", MQTTConnectFlagsTestParse05);
#endif /* UNITTESTS */
}

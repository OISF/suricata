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

#include "rust-bindings.h"

#define PARSE_REGEX "(?: *,?!?(?:username|password|will|will_retain|clean_session))+"
static DetectParseRegex parse_regex;

static int mqtt_connect_flags_id = 0;

static int DetectMQTTConnectFlagsMatch(DetectEngineThreadCtx *det_ctx,
                               Flow *f, uint8_t flags, void *state,
                               void *txv, const Signature *s,
                               const SigMatchCtx *ctx);
static int DetectMQTTConnectFlagsSetup (DetectEngineCtx *, Signature *, const char *);
void MQTTConnectFlagsRegisterTests(void);
void DetectMQTTConnectFlagsFree(void *);

static int DetectEngineInspectMQTTConnectFlagsGeneric(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate,
        void *txv, uint64_t tx_id);

typedef enum {
    DONT_CARE = 0,
    MUST_BE_SET,
    CANT_BE_SET
} MQTTConnectFlagstate;

typedef struct DetectMQTTConnectFlagsData_ {
    MQTTConnectFlagstate username,
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
    sigmatch_table[DETECT_AL_MQTT_CONNECT_FLAGS].url = DOC_URL DOC_VERSION "/rules/mqtt-keywords.html#mqtt-connect-flags";
    sigmatch_table[DETECT_AL_MQTT_CONNECT_FLAGS].AppLayerTxMatch = DetectMQTTConnectFlagsMatch;
    sigmatch_table[DETECT_AL_MQTT_CONNECT_FLAGS].Setup = DetectMQTTConnectFlagsSetup;
    sigmatch_table[DETECT_AL_MQTT_CONNECT_FLAGS].Free  = DetectMQTTConnectFlagsFree;
    sigmatch_table[DETECT_AL_MQTT_CONNECT_FLAGS].RegisterTests = MQTTConnectFlagsRegisterTests;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);

    DetectAppLayerInspectEngineRegister("mqtt.connect.flags",
            ALPROTO_MQTT, SIG_FLAG_TOSERVER, 1,
            DetectEngineInspectMQTTConnectFlagsGeneric);

    mqtt_connect_flags_id = DetectBufferTypeGetByName("mqtt.connect.flags");
}

static int DetectEngineInspectMQTTConnectFlagsGeneric(ThreadVars *tv,
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
    bool username = false, password = false, will = false,
         will_retain = false, clean_session = false;

    if (!de)
        return 0;

    if (rs_mqtt_tx_get_connect_flags(txv, &username, &password, &will,
                                     &will_retain, &clean_session) ==0 ) {
        return 0;
    }

    switch (de->username) {
        case MUST_BE_SET:
            if (!username) return 0;
            break;
        case CANT_BE_SET:
            if (username) return 0;
            break;
        case DONT_CARE:
            break;
    }
    switch (de->password) {
        case MUST_BE_SET:
            if (!password) return 0;
            break;
        case CANT_BE_SET:
            if (password) return 0;
            break;
        case DONT_CARE:
            break;
    }
    switch (de->will_retain) {
        case MUST_BE_SET:
            if (!will_retain) return 0;
            break;
        case CANT_BE_SET:
            if (will_retain) return 0;
            break;
        case DONT_CARE:
            break;
    }
    switch (de->will) {
        case MUST_BE_SET:
            if (!will) return 0;
            break;
        case CANT_BE_SET:
            if (will) return 0;
            break;
        case DONT_CARE:
            break;
    }
    switch (de->clean_session) {
        case MUST_BE_SET:
            if (!clean_session) return 0;
            break;
        case CANT_BE_SET:
            if (clean_session) return 0;
            break;
        case DONT_CARE:
            break;
    }

    return 1;
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
#define MAX_SUBSTRINGS 30
    int ret = 0;
    int ov[MAX_SUBSTRINGS];

    ret = DetectParsePcreExec(&parse_regex, rawstr, 0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 1) {
        SCLogError(SC_ERR_PCRE_MATCH, "invalid flag definition: %s", rawstr);
        return NULL;
    }

    de = SCMalloc(sizeof(DetectMQTTConnectFlagsData));
    if (unlikely(de == NULL))
        return NULL;
    de->username = de->password = de->will = DONT_CARE;
    de->will_retain = de->clean_session = DONT_CARE;

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
            if (flagv[0] == '!') {
                if (strcmp(flagv+1, "username") == 0) {
                    de->username = CANT_BE_SET;
                } else if (strcmp(flagv+1, "password") == 0) {
                    de->password = CANT_BE_SET;
                } else if (strcmp(flagv+1, "will") == 0) {
                    de->will = CANT_BE_SET;
                } else if (strcmp(flagv+1, "will_retain") == 0) {
                    de->will_retain = CANT_BE_SET;
                } else if (strcmp(flagv+1, "clean_session") == 0) {
                    de->clean_session = CANT_BE_SET;
                } else {
                    SCLogError(SC_ERR_UNKNOWN_VALUE, "invalid flag definition: %s", flagv);
                    goto error;
                }
            } else {
                if (strcmp(flagv, "username") == 0) {
                    de->username = MUST_BE_SET;
                } else if (strcmp(flagv, "password") == 0) {
                    de->password = MUST_BE_SET;
                } else if (strcmp(flagv, "will") == 0) {
                    de->will = MUST_BE_SET;
                } else if (strcmp(flagv, "will_retain") == 0) {
                    de->will_retain = MUST_BE_SET;
                } else if (strcmp(flagv, "clean_session") == 0) {
                    de->clean_session = MUST_BE_SET;
                } else {
                    SCLogError(SC_ERR_UNKNOWN_VALUE, "invalid flag definition: %s", flagv);
                    goto error;
                }
            }
        }
        flagv = strtok_r(NULL, ",", &xsaveptr);
    }

    return de;

error:
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
static int DetectMQTTConnectFlagsSetup (DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectMQTTConnectFlagsData *de = NULL;
    SigMatch *sm = NULL;

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
    if (de) SCFree(de);
    if (sm) SCFree(sm);
    return -1;
}

/**
 * \internal
 * \brief this function will free memory associated with DetectMQTTConnectFlagsData
 *
 * \param de pointer to DetectMQTTConnectFlagsData
 */
void DetectMQTTConnectFlagsFree(void *de_ptr)
{
    DetectMQTTConnectFlagsData *de = (DetectMQTTConnectFlagsData *)de_ptr;
    if(de) SCFree(de);
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
    if (!de) {
        return 0;
    }
    DetectMQTTConnectFlagsFree(de);
    de = DetectMQTTConnectFlagsParse("username,password,will,will_retain,clean_session");
   if (!de) {
        return 0;
    }
    DetectMQTTConnectFlagsFree(de);
    de = DetectMQTTConnectFlagsParse("!username,!password,!will,!will_retain,!clean_session");
    if (!de) {
        return 0;
    }
    DetectMQTTConnectFlagsFree(de);
    de = DetectMQTTConnectFlagsParse("   username,password");
    if (!de) {
        return 0;
    }
    DetectMQTTConnectFlagsFree(de);

    return 1;
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
        DetectMQTTConnectFlagsFree(de);
        return 0;
    }

    return 1;
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
        DetectMQTTConnectFlagsFree(de);
        return 0;
    }

    return 1;
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
        DetectMQTTConnectFlagsFree(de);
        return 0;
    }

    return 1;
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
#endif /* UNITTESTS */
}
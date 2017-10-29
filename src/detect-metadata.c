/* Copyright (C) 2007-2017 Open Information Security Foundation
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
 * Implements metadata keyword support
 *
 * \todo Do we need to do anything more this is used in snort host attribute table
 *       It is also used for rule managment.
 */

#include "suricata-common.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-metadata.h"

#include "util-unittest.h"

#define PARSE_REGEX "^\\s*([^\\s]+)\\s+([^\\s]+)(?:,\\s*([^\\s]+)\\s+([^\\s]+))*$"
#define PARSE_TAG_REGEX "\\s*([^\\s]+)\\s+([^,]+)\\s*"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;
static pcre *parse_tag_regex;
static pcre_extra *parse_tag_regex_study;

static int DetectMetadataSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectMetadataRegisterTests(void);

void DetectMetadataRegister (void)
{
    sigmatch_table[DETECT_METADATA].name = "metadata";
    sigmatch_table[DETECT_METADATA].desc = "used by suricata for logging";
    sigmatch_table[DETECT_METADATA].url = DOC_URL DOC_VERSION "/rules/meta.html#metadata";
    sigmatch_table[DETECT_METADATA].Match = NULL;
    sigmatch_table[DETECT_METADATA].Setup = DetectMetadataSetup;
    sigmatch_table[DETECT_METADATA].Free  = NULL;
    sigmatch_table[DETECT_METADATA].RegisterTests = DetectMetadataRegisterTests;

    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex, &parse_regex_study);
    DetectSetupParseRegexes(PARSE_TAG_REGEX, &parse_tag_regex, &parse_tag_regex_study);
}

/**
 *  \brief Free a Metadata object
 */
void DetectMetadataFree(DetectMetadata *mdata)
{
    SCEnter();

    if (mdata->key != NULL) {
        SCFree((void *)mdata->key);
    }
    if (mdata->value != NULL) {
        SCFree((void *)mdata->value);
    }
    SCFree(mdata);

    SCReturn;
}

static int DetectMetadataParse(Signature *s, const char *metadatastr)
{
#define MAX_SUBSTRINGS 30
    int ret = 0, res = 0;
    int ov[MAX_SUBSTRINGS];

    ret = pcre_exec(parse_regex, parse_regex_study, metadatastr,
                    strlen(metadatastr), 0, 0, ov, MAX_SUBSTRINGS);
    if (ret < 2) {
        /* Only warn user that the metadata are not parsed due
         * to invalid format */
        SCLogInfo("signature metadata not in key value format, ret %" PRId32
                    ", string %s", ret, metadatastr);
        return 0;
    }

    char *saveptr = NULL;
    size_t metadatalen = strlen(metadatastr)+1;
    char rawstr[metadatalen];
    strlcpy(rawstr, metadatastr, metadatalen);
    char * kv = strtok_r(rawstr, ",", &saveptr);
    const char *key = NULL;
    const char *value = NULL;
    char pkey[256];
    char pvalue[256];

    /* now check key value */
    do {
        DetectMetadata *dkv;

        ret = pcre_exec(parse_tag_regex, parse_tag_regex_study, kv, strlen(kv), 0, 0, ov, MAX_SUBSTRINGS);
        if (ret < 2) {
            SCLogError(SC_ERR_PCRE_MATCH, "pcre_exec parse error, ret %" PRId32
                    ", string %s", ret, rawstr);
            goto error;
        }

        res =  pcre_copy_substring(kv, ov, MAX_SUBSTRINGS, 1, pkey, sizeof(pkey));
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
            goto error;
        }
        key = SCStrdup(pkey);
        if (key == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "can't create metadata key");
            goto error;
        }

        res =  pcre_copy_substring(kv, ov, MAX_SUBSTRINGS, 2, pvalue, sizeof(pvalue));
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_copy_substring failed");
            goto error;
        }
        value = SCStrdup(pvalue);
        if (value == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "can't create metadata value");
            goto error;
        }

        SCLogDebug("key: %s, value: %s", key, value);

        dkv = SCMalloc(sizeof(DetectMetadata));
        if (dkv) {
            dkv->key = key;
            if (!dkv->key) {
                SCFree(dkv);
            } else {
                dkv->value = value;
                if (!dkv->value) {
                    SCFree((void *)dkv->key);
                    SCFree(dkv);
                } else {
                    dkv->next = s->metadata;
                    s->metadata = dkv;
                }
            }
        } else {
            goto error;
        }

        kv = strtok_r(NULL, ",", &saveptr);
    } while (kv);

    return 0;

error:
    if (key)
        SCFree((void *)key);
    if (value)
        SCFree((void *)value);
    return -1;
}

static int DetectMetadataSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    if (DetectEngineMustParseMetadata()) {
        DetectMetadataParse(s, rawstr);
    }

    return 0;
}

#ifdef UNITTESTS

static int DetectMetadataParseTest01(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    int prev_state = 0;

    if (DetectEngineMustParseMetadata()) {
        prev_state = 1;
        DetectEngineUnsetParseMetadata();
    }
    Signature *sig = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (metadata: toto 1; sid:1; rev:1;)");
    if (prev_state == 1) {
        DetectEngineSetParseMetadata();
    }
    FAIL_IF_NULL(sig);
    FAIL_IF(sig->metadata); 

    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectMetadataParseTest02(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    DetectMetadata *dm;
    int prev_state = 1;

    if (! DetectEngineMustParseMetadata()) {
        prev_state = 0;
        DetectEngineSetParseMetadata();
    }

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    Signature *sig = DetectEngineAppendSig(de_ctx, "alert tcp any any -> any any (metadata: toto 1; metadata: titi 2, jaivu gros_minet; sid:1; rev:1;)");
    if (prev_state == 0) {
        DetectEngineUnsetParseMetadata();
    }
    FAIL_IF_NULL(sig);
    FAIL_IF_NULL(sig->metadata); 
    FAIL_IF_NULL(sig->metadata->key); 
    FAIL_IF(strcmp("jaivu", sig->metadata->key));
    FAIL_IF(strcmp("gros_minet", sig->metadata->value));
    FAIL_IF_NULL(sig->metadata->next); 
    dm = sig->metadata->next;
    FAIL_IF(strcmp("titi", dm->key));
    dm = dm->next;
    FAIL_IF_NULL(dm);
    FAIL_IF(strcmp("toto", dm->key));

    DetectEngineCtxFree(de_ctx);
    PASS;
}

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectCipService
 */
static void DetectMetadataRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("DetectMetadataParseTest01", DetectMetadataParseTest01);
    UtRegisterTest("DetectMetadataParseTest02", DetectMetadataParseTest02);
#endif /* UNITTESTS */
}


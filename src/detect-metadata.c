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
#include "detect-metadata.h"

#define PARSE_REGEX "^\\s*([^\\s]+)\\s+([^\\s]+)(?:,\\s*([^\\s]+)\\s+([^\\s]+))*$"
#define PARSE_TAG_REGEX "\\s*([^\\s]+)\\s+([^,]+)\\s*"

static pcre *parse_regex;
static pcre_extra *parse_regex_study;
static pcre *parse_tag_regex;
static pcre_extra *parse_tag_regex_study;

static int DetectMetadataSetup (DetectEngineCtx *, Signature *, const char *);

void DetectMetadataRegister (void)
{
    sigmatch_table[DETECT_METADATA].name = "metadata";
    sigmatch_table[DETECT_METADATA].desc = "partially used by suricata";
    sigmatch_table[DETECT_METADATA].url = DOC_URL DOC_VERSION "/rules/meta.html#metadata";
    sigmatch_table[DETECT_METADATA].Match = NULL;
    sigmatch_table[DETECT_METADATA].Setup = DetectMetadataSetup;
    sigmatch_table[DETECT_METADATA].Free  = NULL;
    sigmatch_table[DETECT_METADATA].RegisterTests = NULL;

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
        pcre_free_substring(mdata->key);
    }
    if (mdata->value != NULL) {
        pcre_free_substring(mdata->value);
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
        SCLogError(SC_ERR_PCRE_MATCH, "pcre_exec parse error, ret %" PRId32
                ", string %s", ret, metadatastr);
        return -1;
    }

    char *saveptr = NULL;
    size_t metadatalen = strlen(metadatastr)+1;
    char rawstr[metadatalen];
    strlcpy(rawstr, metadatastr, metadatalen);
    char * kv = strtok_r(rawstr, ",", &saveptr);
    const char *key = NULL;
    const char *value = NULL;

    /* now check key value */
    do {
        DetectMetadata *dkv;

        ret = pcre_exec(parse_tag_regex, parse_tag_regex_study, kv, strlen(kv), 0, 0, ov, MAX_SUBSTRINGS);
        if (ret < 2) {
            SCLogError(SC_ERR_PCRE_MATCH, "pcre_exec parse error, ret %" PRId32
                    ", string %s", ret, rawstr);
            goto error;
        }

        res =  pcre_get_substring(kv, ov, MAX_SUBSTRINGS, 1, &key);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
            goto error;
        }

        res =  pcre_get_substring(kv, ov, MAX_SUBSTRINGS, 2, &value);
        if (res < 0) {
            SCLogError(SC_ERR_PCRE_GET_SUBSTRING, "pcre_get_substring failed");
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
                    pcre_free_substring(dkv->key);
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
        pcre_free_substring(key);
    if (value)
        pcre_free_substring(value);
    return -1;
}

static int DetectMetadataSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    DetectMetadataParse(s, rawstr);

    return 0;
}


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
#include "util-hash-string.h"
#include "util-unittest.h"

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
}

/**
 *  \brief Free a Metadata object
 */
void DetectMetadataFree(DetectMetadata *mdata)
{
    SCEnter();

    SCFree(mdata);

    SCReturn;
}

int DetectMetadataHashInit(DetectEngineCtx *de_ctx)
{
    if (! DetectEngineMustParseMetadata())
        return 0;

    de_ctx->metadata_table = HashTableInit(4096, StringHashFunc, StringHashCompareFunc, StringHashFreeFunc);
    if (de_ctx->metadata_table == NULL)
        return -1;
    return 0;
}

void DetectMetadataHashFree(DetectEngineCtx *de_ctx)
{
    if (de_ctx->metadata_table)
        HashTableFree(de_ctx->metadata_table);
}

static const char *DetectMedatataHashAdd(DetectEngineCtx *de_ctx, const char *string)
{
    const char * hstring = (char *)HashTableLookup(de_ctx->metadata_table, (void *)string, strlen(string));
    if (hstring) {
        return hstring;
    }

    const char *astring = SCStrdup(string);
    if (astring == NULL) {
        return NULL;
    }

    if (HashTableAdd(de_ctx->metadata_table, (void *)astring, strlen(astring)) == 0) {
        return (char *)HashTableLookup(de_ctx->metadata_table, (void *)astring, strlen(astring));
    } else {
        SCFree((void *)astring);
    }
    return NULL;
}

static int DetectMetadataParse(DetectEngineCtx *de_ctx, Signature *s, const char *metadatastr)
{
    char copy[strlen(metadatastr)+1];
    strlcpy(copy, metadatastr, sizeof(copy));
    char *xsaveptr = NULL;
    char *key = strtok_r(copy, ",", &xsaveptr);
    while (key != NULL) {
        while (*key != '\0' && isblank(*key)) {
            key++;
        }
        char *val = strchr(key, ' ');
        if (val != NULL) {
            *val++ = '\0';
            while (*val != '\0' && isblank(*val)) {
                val++;
            }
        } else {
            /* Skip metadata without a value. */
            goto next;
        }

        /* Also skip metadata if the key or value is empty. */
        if (strlen(key) == 0 || strlen(val) == 0) {
            goto next;
        }

        const char *hkey = DetectMedatataHashAdd(de_ctx, key);
        if (hkey == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "can't create metadata key");
            continue;
        }

        const char *hval = DetectMedatataHashAdd(de_ctx, val);
        if (hval == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "can't create metadata value");
            goto next;
        }

        SCLogDebug("key: %s, value: %s", hkey, hval);

        DetectMetadata *dkv = SCMalloc(sizeof(DetectMetadata));
        if (dkv == NULL) {
            goto next;
        }
        dkv->key = hkey;
        dkv->value = hval;
        dkv->next = s->metadata;
        s->metadata = dkv;

    next:
        key = strtok_r(NULL, ",", &xsaveptr);
    }

    return 0;
}

static int DetectMetadataSetup(DetectEngineCtx *de_ctx, Signature *s, const char *rawstr)
{
    if (DetectEngineMustParseMetadata()) {
        DetectMetadataParse(de_ctx, s, rawstr);
    }

    return 0;
}

#ifdef UNITTESTS

static int DetectMetadataParseTest01(void)
{
    DetectEngineUnsetParseMetadata();
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);

    Signature *sig = DetectEngineAppendSig(de_ctx,
                                           "alert tcp any any -> any any "
                                           "(metadata: toto 1; sid:1; rev:1;)");
    FAIL_IF_NULL(sig);
    FAIL_IF(sig->metadata); 

    DetectEngineCtxFree(de_ctx);
    PASS;
}

static int DetectMetadataParseTest02(void)
{
    DetectEngineSetParseMetadata();
    DetectEngineCtx *de_ctx = NULL;
    DetectMetadata *dm;

    de_ctx = DetectEngineCtxInit();
    FAIL_IF_NULL(de_ctx);
    Signature *sig = DetectEngineAppendSig(de_ctx,
                                           "alert tcp any any -> any any "
                                           "(metadata: toto 1; "
                                           "metadata: titi 2, jaivu gros_minet;"
                                           "sid:1; rev:1;)");
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


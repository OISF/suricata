/* Copyright (C) 2007-2016 Open Information Security Foundation
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
 * \author Duarte Silva <duarte.silva@serializing.me>
 *
 */

#include "suricata-common.h"

#include "detect-engine.h"
#include "detect-file-hash-common.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "detect-filesha1.h"

#ifndef HAVE_NSS

static int DetectFileSha1SetupNoSupport (DetectEngineCtx *a, Signature *b, const char *c)
{
    SCLogError(SC_ERR_NO_SHA1_SUPPORT, "no SHA-1 calculation support built in, needed for filesha1 keyword");
    return -1;
}

/**
 * \brief Registration function for keyword: filesha1
 */
void DetectFileSha1Register(void)
{
    sigmatch_table[DETECT_FILESHA1].name = "filesha1";
    sigmatch_table[DETECT_FILESHA1].FileMatch = NULL;
    sigmatch_table[DETECT_FILESHA1].Setup = DetectFileSha1SetupNoSupport;
    sigmatch_table[DETECT_FILESHA1].Free  = NULL;
    sigmatch_table[DETECT_FILESHA1].RegisterTests = NULL;
    sigmatch_table[DETECT_FILESHA1].flags = SIGMATCH_NOT_BUILT;

    SCLogDebug("registering filesha1 rule option");
    return;
}

#else /* HAVE_NSS */

static int DetectFileSha1Setup (DetectEngineCtx *, Signature *, const char *);
static void DetectFileSha1RegisterTests(void);
static int g_file_match_list_id = 0;

/**
 * \brief Registration function for keyword: filesha1
 */
void DetectFileSha1Register(void)
{
    sigmatch_table[DETECT_FILESHA1].name = "filesha1";
    sigmatch_table[DETECT_FILESHA1].desc = "match file SHA-1 against list of SHA-1 checksums";
    sigmatch_table[DETECT_FILESHA1].url = DOC_URL DOC_VERSION "/rules/file-keywords.html#filesha1";
    sigmatch_table[DETECT_FILESHA1].FileMatch = DetectFileHashMatch;
    sigmatch_table[DETECT_FILESHA1].Setup = DetectFileSha1Setup;
    sigmatch_table[DETECT_FILESHA1].Free  = DetectFileHashFree;
    sigmatch_table[DETECT_FILESHA1].RegisterTests = DetectFileSha1RegisterTests;

    g_file_match_list_id = DetectBufferTypeRegister("files");

    SCLogDebug("registering filesha1 rule option");
    return;
}

/**
 * \brief this function is used to parse filesha1 options
 * \brief into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param str pointer to the user provided "filesha1" option
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectFileSha1Setup (DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    return DetectFileHashSetup(de_ctx, s, str, DETECT_FILESHA1, g_file_match_list_id);
}

#ifdef UNITTESTS
static int SHA1MatchLookupString(ROHashTable *hash, const char *string)
{
    uint8_t sha1[20];
    if (ReadHashString(sha1, string, "file", 88, 40) == 1) {
        void *ptr = ROHashLookup(hash, &sha1, (uint16_t)sizeof(sha1));
        if (ptr == NULL)
            return 0;
        else
            return 1;
    }
    return 0;
}

static int SHA1MatchTest01(void)
{
    ROHashTable *hash = ROHashInit(4, 20);
    if (hash == NULL) {
        return 0;
    }
    if (LoadHashTable(hash, "447661c5de965bd4d837b50244467e37bddc184d", "file", 1, DETECT_FILESHA1) != 1)
        return 0;
    if (LoadHashTable(hash, "75a9af1e34dc0bb2f7fcde9d56b2503072ac35dd", "file", 2, DETECT_FILESHA1) != 1)
        return 0;
    if (LoadHashTable(hash, "53224a297bbb30631670fdcd2d295d87a1d328e9", "file", 3, DETECT_FILESHA1) != 1)
        return 0;
    if (LoadHashTable(hash, "3395856ce81f2b7382dee72602f798b642f14140", "file", 4, DETECT_FILESHA1) != 1)
        return 0;
    if (LoadHashTable(hash, "65559245709fe98052eb284577f1fd61c01ad20d", "file", 5, DETECT_FILESHA1) != 1)
        return 0;
    if (LoadHashTable(hash, "0931fd4e05e6ea81c75f8488ecc1db9e66f22cbb", "file", 6, DETECT_FILESHA1) != 1)
        return 0;

    if (ROHashInitFinalize(hash) != 1) {
        return 0;
    }

    if (SHA1MatchLookupString(hash, "447661c5de965bd4d837b50244467e37bddc184d") != 1)
        return 0;
    if (SHA1MatchLookupString(hash, "75a9af1e34dc0bb2f7fcde9d56b2503072ac35dd") != 1)
        return 0;
    if (SHA1MatchLookupString(hash, "53224a297bbb30631670fdcd2d295d87a1d328e9") != 1)
        return 0;
    if (SHA1MatchLookupString(hash, "3395856ce81f2b7382dee72602f798b642f14140") != 1)
        return 0;
    if (SHA1MatchLookupString(hash, "65559245709fe98052eb284577f1fd61c01ad20d") != 1)
        return 0;
    if (SHA1MatchLookupString(hash, "0931fd4e05e6ea81c75f8488ecc1db9e66f22cbb") != 1)
        return 0;
    /* Shouldn't match */
    if (SHA1MatchLookupString(hash, "3333333333333333333333333333333333333333") == 1)
        return 0;

    ROHashFree(hash);
    return 1;
}
#endif

void DetectFileSha1RegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("SHA1MatchTest01", SHA1MatchTest01);
#endif
}

#endif /* HAVE_NSS */

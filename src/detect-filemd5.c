/* Copyright (C) 2007-2012 Open Information Security Foundation
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
 */

#include "suricata-common.h"

#include "detect-engine.h"
#include "detect-file-hash-common.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "detect-filemd5.h"

static int g_file_match_list_id = 0;

static int DetectFileMd5Setup (DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectFileMd5RegisterTests(void);
#endif

/**
 * \brief Registration function for keyword: filemd5
 */
void DetectFileMd5Register(void)
{
    sigmatch_table[DETECT_FILEMD5].name = "filemd5";
    sigmatch_table[DETECT_FILEMD5].desc = "match file MD5 against list of MD5 checksums";
    sigmatch_table[DETECT_FILEMD5].url = "/rules/file-keywords.html#filemd5";
    sigmatch_table[DETECT_FILEMD5].FileMatch = DetectFileHashMatch;
    sigmatch_table[DETECT_FILEMD5].Setup = DetectFileMd5Setup;
    sigmatch_table[DETECT_FILEMD5].Free  = DetectFileHashFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_FILEMD5].RegisterTests = DetectFileMd5RegisterTests;
#endif
    g_file_match_list_id = DetectBufferTypeRegister("files");

    SCLogDebug("registering filemd5 rule option");
    return;
}

/**
 * \brief this function is used to parse filemd5 options
 * \brief into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param str pointer to the user provided "filemd5" option
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectFileMd5Setup (DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    return DetectFileHashSetup(de_ctx, s, str, DETECT_FILEMD5, g_file_match_list_id);
}

#ifdef UNITTESTS
static int MD5MatchLookupString(ROHashTable *hash, const char *string)
{
    uint8_t md5[16];
    if (ReadHashString(md5, string, "file", 88, 32) == 1) {
        void *ptr = ROHashLookup(hash, &md5, (uint16_t)sizeof(md5));
        if (ptr == NULL)
            return 0;
        else
            return 1;
    }
    return 0;
}

static int MD5MatchTest01(void)
{
    ROHashTable *hash = ROHashInit(4, 16);
    FAIL_IF_NULL(hash);
    FAIL_IF(LoadHashTable(hash, "d80f93a93dc5f3ee945704754d6e0a36", "file", 1, DETECT_FILEMD5) !=
            1);
    FAIL_IF(LoadHashTable(hash, "92a49985b384f0d993a36e4c2d45e206", "file", 2, DETECT_FILEMD5) !=
            1);
    FAIL_IF(LoadHashTable(hash, "11adeaacc8c309815f7bc3e33888f281", "file", 3, DETECT_FILEMD5) !=
            1);
    FAIL_IF(LoadHashTable(hash, "22e10a8fe02344ade0bea8836a1714af", "file", 4, DETECT_FILEMD5) !=
            1);
    FAIL_IF(LoadHashTable(hash, "c3db2cbf02c68f073afcaee5634677bc", "file", 5, DETECT_FILEMD5) !=
            1);
    FAIL_IF(LoadHashTable(hash, "7ed095da259638f42402fb9e74287a17", "file", 6, DETECT_FILEMD5) !=
            1);
    FAIL_IF(ROHashInitFinalize(hash) != 1);
    FAIL_IF(MD5MatchLookupString(hash, "d80f93a93dc5f3ee945704754d6e0a36") != 1);
    FAIL_IF(MD5MatchLookupString(hash, "92a49985b384f0d993a36e4c2d45e206") != 1);
    FAIL_IF(MD5MatchLookupString(hash, "11adeaacc8c309815f7bc3e33888f281") != 1);
    FAIL_IF(MD5MatchLookupString(hash, "22e10a8fe02344ade0bea8836a1714af") != 1);
    FAIL_IF(MD5MatchLookupString(hash, "c3db2cbf02c68f073afcaee5634677bc") != 1);
    FAIL_IF(MD5MatchLookupString(hash, "7ed095da259638f42402fb9e74287a17") != 1);
    FAIL_IF(MD5MatchLookupString(hash, "33333333333333333333333333333333") == 1);
    ROHashFree(hash);
    PASS;
}

void DetectFileMd5RegisterTests(void)
{
    UtRegisterTest("MD5MatchTest01", MD5MatchTest01);
}
#endif

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

#include "detect-filesha256.h"

static int DetectFileSha256Setup (DetectEngineCtx *, Signature *, const char *);
#ifdef UNITTESTS
static void DetectFileSha256RegisterTests(void);
#endif
static int g_file_match_list_id = 0;

/**
 * \brief Registration function for keyword: filesha256
 */
void DetectFileSha256Register(void)
{
    sigmatch_table[DETECT_FILESHA256].name = "filesha256";
    sigmatch_table[DETECT_FILESHA256].desc = "match file SHA-256 against list of SHA-256 checksums";
    sigmatch_table[DETECT_FILESHA256].url = "/rules/file-keywords.html#filesha256";
    sigmatch_table[DETECT_FILESHA256].FileMatch = DetectFileHashMatch;
    sigmatch_table[DETECT_FILESHA256].Setup = DetectFileSha256Setup;
    sigmatch_table[DETECT_FILESHA256].Free  = DetectFileHashFree;
#ifdef UNITTESTS
    sigmatch_table[DETECT_FILESHA256].RegisterTests = DetectFileSha256RegisterTests;
#endif

    g_file_match_list_id = DetectBufferTypeRegister("files");

    SCLogDebug("registering filesha256 rule option");
    return;
}

/**
 * \brief this function is used to parse filesha256 options
 * \brief into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param str pointer to the user provided "filesha256" option
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectFileSha256Setup (DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    return DetectFileHashSetup(de_ctx, s, str, DETECT_FILESHA256, g_file_match_list_id);
}

#ifdef UNITTESTS
static int SHA256MatchLookupString(ROHashTable *hash, const char *string)
{
    uint8_t sha256[32];
    if (ReadHashString(sha256, string, "file", 88, 64) == 1) {
        void *ptr = ROHashLookup(hash, &sha256, (uint16_t)sizeof(sha256));
        if (ptr == NULL)
            return 0;
        else
            return 1;
    }
    return 0;
}

static int SHA256MatchTest01(void)
{
    ROHashTable *hash = ROHashInit(4, 32);
    FAIL_IF_NULL(hash);
    FAIL_IF(LoadHashTable(hash, "9c891edb5da763398969b6aaa86a5d46971bd28a455b20c2067cb512c9f9a0f8",
                    "file", 1, DETECT_FILESHA256) != 1);
    FAIL_IF(LoadHashTable(hash, "6eee51705f34b6cfc7f0c872a7949ec3e3172a908303baf5d67d03b98f70e7e3",
                    "file", 2, DETECT_FILESHA256) != 1);
    FAIL_IF(LoadHashTable(hash, "b12c7d57507286bbbe36d7acf9b34c22c96606ffd904e3c23008399a4a50c047",
                    "file", 3, DETECT_FILESHA256) != 1);
    FAIL_IF(LoadHashTable(hash, "ca496e1ddadc290050339dd75ce8830ad3028ce1556a5368874a4aec3aee114b",
                    "file", 4, DETECT_FILESHA256) != 1);
    FAIL_IF(LoadHashTable(hash, "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
                    "file", 5, DETECT_FILESHA256) != 1);
    FAIL_IF(LoadHashTable(hash, "d765e722e295969c0a5c2d90f549db8b89ab617900bf4698db41c7cdad993bb9",
                    "file", 6, DETECT_FILESHA256) != 1);
    FAIL_IF(ROHashInitFinalize(hash) != 1);
    FAIL_IF(SHA256MatchLookupString(
                    hash, "9c891edb5da763398969b6aaa86a5d46971bd28a455b20c2067cb512c9f9a0f8") != 1);
    FAIL_IF(SHA256MatchLookupString(
                    hash, "6eee51705f34b6cfc7f0c872a7949ec3e3172a908303baf5d67d03b98f70e7e3") != 1);
    FAIL_IF(SHA256MatchLookupString(
                    hash, "b12c7d57507286bbbe36d7acf9b34c22c96606ffd904e3c23008399a4a50c047") != 1);
    FAIL_IF(SHA256MatchLookupString(
                    hash, "ca496e1ddadc290050339dd75ce8830ad3028ce1556a5368874a4aec3aee114b") != 1);
    FAIL_IF(SHA256MatchLookupString(
                    hash, "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f") != 1);
    FAIL_IF(SHA256MatchLookupString(
                    hash, "d765e722e295969c0a5c2d90f549db8b89ab617900bf4698db41c7cdad993bb9") != 1);
    /* Shouldn't match */
    FAIL_IF(SHA256MatchLookupString(
                    hash, "3333333333333333333333333333333333333333333333333333333333333333") == 1);
    ROHashFree(hash);
    PASS;
}

void DetectFileSha256RegisterTests(void)
{
    UtRegisterTest("SHA256MatchTest01", SHA256MatchTest01);
}
#endif

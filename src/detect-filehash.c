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
 * \author Duarte Silva <duarte.silva"serializing.me>
 *
 */

#include "suricata-common.h"
#include "threads.h"
#include "debug.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "util-debug.h"
#include "util-spm-bm.h"
#include "util-print.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "app-layer.h"

#include "stream-tcp.h"

#include "detect-filehash.h"

#include "queue.h"
#include "util-rohash.h"

#ifndef HAVE_NSS

static int DetectFileHashSetupNoSupport (DetectEngineCtx *a, Signature *b, char *c)
{
    SCLogError(SC_ERR_NO_HASH_SUPPORT, "no file hash calculation support built in, needed for filemd5, filesha1 and filesha256 keyword");
    return -1;
}

/**
 * \brief Registration function for keyword: filemd5, filesha1 and filesha256
 */
void DetectFileHashRegister(void)
{
    sigmatch_table[DETECT_FILEMD5].name = "filemd5";
    sigmatch_table[DETECT_FILEMD5].FileMatch = NULL;
    sigmatch_table[DETECT_FILEMD5].alproto = ALPROTO_HTTP;
    sigmatch_table[DETECT_FILEMD5].Setup = DetectFileHashSetupNoSupport;
    sigmatch_table[DETECT_FILEMD5].Free  = NULL;
    sigmatch_table[DETECT_FILEMD5].RegisterTests = NULL;
    sigmatch_table[DETECT_FILEMD5].flags = SIGMATCH_NOT_BUILT;

    sigmatch_table[DETECT_FILESHA1].name = "filesha1";
    sigmatch_table[DETECT_FILESHA1].FileMatch = NULL;
    sigmatch_table[DETECT_FILESHA1].alproto = ALPROTO_HTTP;
    sigmatch_table[DETECT_FILESHA1].Setup = DetectFileHashSetupNoSupport;
    sigmatch_table[DETECT_FILESHA1].Free  = NULL;
    sigmatch_table[DETECT_FILESHA1].RegisterTests = NULL;
    sigmatch_table[DETECT_FILESHA1].flags = SIGMATCH_NOT_BUILT;

    sigmatch_table[DETECT_FILESHA256].name = "filesha256";
    sigmatch_table[DETECT_FILESHA256].FileMatch = NULL;
    sigmatch_table[DETECT_FILESHA256].alproto = ALPROTO_HTTP;
    sigmatch_table[DETECT_FILESHA256].Setup = DetectFileHashSetupNoSupport;
    sigmatch_table[DETECT_FILESHA256].Free  = NULL;
    sigmatch_table[DETECT_FILESHA256].RegisterTests = NULL;
    sigmatch_table[DETECT_FILESHA256].flags = SIGMATCH_NOT_BUILT;

    SCLogDebug("registering filemd5, filesha1 and filesha256 rule option");
    return;
}

#else /* HAVE_NSS */

static int DetectFileHashMatch (ThreadVars *, DetectEngineThreadCtx *,
        Flow *, uint8_t, File *, Signature *, SigMatch *);
static int DetectFileMd5Setup (DetectEngineCtx *, Signature *, char *);
static int DetectFileSha1Setup (DetectEngineCtx *, Signature *, char *);
static int DetectFileSha256Setup (DetectEngineCtx *, Signature *, char *);
static void DetectFileMd5RegisterTests(void);
static void DetectFileSha1RegisterTests(void);
static void DetectFileSha256RegisterTests(void);
static void DetectFileHashFree(void *);

/**
 * \brief Registration function for keyword: filemd5
 */
void DetectFileHashRegister(void)
{
    sigmatch_table[DETECT_FILEMD5].name = "filemd5";
    sigmatch_table[DETECT_FILEMD5].desc = "match file MD5 against list of MD5 checksums";
    sigmatch_table[DETECT_FILEMD5].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/File-keywords#filemd5";
    sigmatch_table[DETECT_FILEMD5].FileMatch = DetectFileHashMatch;
    sigmatch_table[DETECT_FILEMD5].alproto = ALPROTO_HTTP;
    sigmatch_table[DETECT_FILEMD5].Setup = DetectFileMd5Setup;
    sigmatch_table[DETECT_FILEMD5].Free  = DetectFileHashFree;
    sigmatch_table[DETECT_FILEMD5].RegisterTests = DetectFileMd5RegisterTests;

    sigmatch_table[DETECT_FILESHA1].name = "filesha1";
    sigmatch_table[DETECT_FILESHA1].desc = "match file SHA1 against list of SHA1 checksums";
    sigmatch_table[DETECT_FILESHA1].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/File-keywords#filesha1";
    sigmatch_table[DETECT_FILESHA1].FileMatch = DetectFileHashMatch;
    sigmatch_table[DETECT_FILESHA1].alproto = ALPROTO_HTTP;
    sigmatch_table[DETECT_FILESHA1].Setup = DetectFileSha1Setup;
    sigmatch_table[DETECT_FILESHA1].Free  = DetectFileHashFree;
    sigmatch_table[DETECT_FILESHA1].RegisterTests = DetectFileSha1RegisterTests;

    sigmatch_table[DETECT_FILESHA256].name = "filesha256";
    sigmatch_table[DETECT_FILESHA256].desc = "match file SHA256 against list of SHA256 checksums";
    sigmatch_table[DETECT_FILESHA256].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/File-keywords#filesha256";
    sigmatch_table[DETECT_FILESHA256].FileMatch = DetectFileHashMatch;
    sigmatch_table[DETECT_FILESHA256].alproto = ALPROTO_HTTP;
    sigmatch_table[DETECT_FILESHA256].Setup = DetectFileSha256Setup;
    sigmatch_table[DETECT_FILESHA256].Free  = DetectFileHashFree;
    sigmatch_table[DETECT_FILESHA256].RegisterTests = DetectFileSha256RegisterTests;

    SCLogDebug("registering filemd5, filesha1 and filesha256 rule option");
    return;
}

/**
 * \brief Read the bytes of a hash from an hexadecimal string
 * 
 * \param hash buffer to store the resulting bytes
 * \param string hexadecimal string representing the hash
 * \param filename file name from where the string was read
 * \param line_no file line number from where the string was read
 * \param expected_len the expected length of the string that was read
 *
 * \retval -1 the hexadecimal string is invalid
 * \retval 1 the hexadecimal string was read successfully
 */
static int ReadHashString(uint8_t *hash, char *string, char *filename, int line_no,
        uint16_t expected_len)
{
    if (strlen(string) != expected_len) {
        SCLogError(SC_ERR_INVALID_HASH, "%s:%d hash string not %d characters",
                filename, line_no, expected_len);
        return -1;
    }

    int i, x;
    for (x = 0, i = 0; i < expected_len; i+=2, x++) {
        char buf[3] = { 0, 0, 0 };
        buf[0] = string[i];
        buf[1] = string[i+1];

        long value = strtol(buf, NULL, 16);
        if (value >= 0 && value <= 255)
            hash[x] = (uint8_t)value;
        else {
            SCLogError(SC_ERR_INVALID_HASH, "%s:%d hash byte out of range %ld",
                    filename, line_no, value);
            return -1;
        }
    }

    return 1;
}

/**
 * \brief Store a hash into the hash table
 * 
 * \param hash_table hash table that will hold the hash
 * \param string hexadecimal string representing the hash
 * \param filename file name from where the string was read
 * \param line_no file line number from where the string was read
 * \param type the hash algorithm
 *
 * \retval -1 failed to load the hash into the hash table
 * \retval 1 successfully loaded the has into the hash table
 */
static int LoadHashTable(ROHashTable *hash_table, char *string, char *filename,
        int line_no, uint32_t type)
{
    /* allocate the maximum size a hash can have (in this case is SHA256, 32 bytes) */
    uint8_t hash[32];
    /* specify the actual size that should be read depending on the hash algorithm */
    uint16_t size = 32;
    
    if (type == DETECT_FILEMD5) {
        size = 16;
    }
    else if (type == DETECT_FILESHA1) {
        size = 20;
    }
    
    /* every byte represented with hexadecimal digits is two characters */
    uint16_t expected_len = (size * 2);

    if (ReadHashString(hash, string, filename, line_no, expected_len) == 1) {
        if (ROHashInitQueueValue(hash_table, &hash, size) != 1)
            return -1;
    }

    return 1;
}

/**
 * \brief Match a hash stored in a hash table
 * 
 * \param hash_table hash table that will hold the hash
 * \param hash buffer containing the bytes of the has
 * \param hash_len length of the hash buffer
 *
 * \retval 0 didn't find the specified hash
 * \retval 1 the hash matched a stored value
 */
static int HashMatchHashTable(ROHashTable *hash_table, uint8_t *hash,
        size_t hash_len)
{
    void *ptr = ROHashLookup(hash_table, hash, (uint16_t)hash_len);
    if (ptr == NULL)
        return 0;
    else
        return 1;
}

/**
 * \brief Match the specified file hash
 *
 * \param t thread local vars
 * \param det_ctx pattern matcher thread local data
 * \param f *LOCKED* flow
 * \param flags direction flags
 * \param file file being inspected
 * \param s signature being inspected
 * \param m sigmatch that we will cast into DetectFileHashData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectFileHashMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, File *file, Signature *s, SigMatch *m)
{
    SCEnter();
    int ret = 0;
    DetectFileHashData *filehash = (DetectFileHashData *)m->ctx;

    if (file->txid < det_ctx->tx_id) {
        SCReturnInt(0);
    }

    if (file->txid > det_ctx->tx_id) {
        SCReturnInt(0);
    }

    if (file->state != FILE_STATE_CLOSED) {
        SCReturnInt(0);
    }

    int match = -1;
        
    if (file->flags & FILE_MD5) {
        match = HashMatchHashTable(filehash->hash, file->md5, sizeof(file->md5));
    }
    else if (file->flags & FILE_SHA1) {
        match = HashMatchHashTable(filehash->hash, file->sha1, sizeof(file->sha1));
    }
    else if (file->flags & FILE_SHA256) {
        match = HashMatchHashTable(filehash->hash, file->sha256, sizeof(file->sha256));
    }

    if (match == 1) {
        if (filehash->negated == 0)
            ret = 1;
        else
            ret = 0;
    }
    else if (match == 0) {
        if (filehash->negated == 0)
            ret = 0;
        else
            ret = 1;
    }

    SCReturnInt(ret);
}

/**
 * \brief Parse the filemd5 keyword
 *
 * \param idstr Pointer to the user provided option
 *
 * \retval filemd5 pointer to DetectFileHashData on success
 * \retval NULL on failure
 */
static DetectFileHashData *DetectFileHashParse (const DetectEngineCtx *de_ctx,
        char *str, uint8_t type)
{
    DetectFileHashData *filehash = NULL;
    FILE *fp = NULL;
    char *filename = NULL;

    /* We have a correct filemd5 option */
    filehash = SCMalloc(sizeof(DetectFileHashData));
    if (unlikely(filehash == NULL))
        goto error;

    memset(filehash, 0x00, sizeof(DetectFileHashData));

    if (strlen(str) && str[0] == '!') {
        filehash->negated = 1;
        str++;
    }

    if (type == DETECT_FILEMD5) {
        filehash->hash = ROHashInit(18, 16);
    }
    else if (type == DETECT_FILESHA1) {
        filehash->hash = ROHashInit(18, 20);        
    }
    else if (type == DETECT_FILESHA256) {
        filehash->hash = ROHashInit(18, 32);        
    }

    if (filehash->hash == NULL) {
        goto error;
    }

    /* get full filename */
    filename = DetectLoadCompleteSigPath(de_ctx, str);
    if (filename == NULL) {
        goto error;
    }

    char line[8192] = "";
    fp = fopen(filename, "r");
    if (fp == NULL) {
        SCLogError(SC_ERR_OPENING_RULE_FILE, "opening hash file %s: %s", filename, strerror(errno));
        goto error;
    }

    int line_no = 0;
    while(fgets(line, (int)sizeof(line), fp) != NULL) {
        size_t len = strlen(line);
        line_no++;

        /* ignore comments and empty lines */
        if (line[0] == '\n' || line [0] == '\r' || line[0] == ' ' || line[0] == '#' || line[0] == '\t')
            continue;

        while (isspace(line[--len]));

        /* Check if we have a trailing newline, and remove it */
        len = strlen(line);
        if (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[len - 1] = '\0';
        }

        /* cut off longer lines than a SHA256 represented in hexadecimal  */
        if (strlen(line) > 64)
            line[64] = 0x00;

        if (LoadHashTable(filehash->hash, line, filename, line_no, type) != 1) {
            goto error;
        }
    }
    fclose(fp);
    fp = NULL;

    if (ROHashInitFinalize(filehash->hash) != 1) {
        goto error;
    }
    SCLogInfo("Hash hash table size %u bytes%s", ROHashMemorySize(filehash->hash), filehash->negated ? ", negated match" : "");

    SCFree(filename);
    return filehash;

error:
    if (filehash != NULL)
        DetectFileHashFree(filehash);
    if (fp != NULL)
        fclose(fp);
    if (filename != NULL)
        SCFree(filename);
    return NULL;
}

/**
 * \brief this function is used to parse filemd5, filesha1 and filesha256 options
 * \brief into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param str pointer to the user provided "filemd5", "filesha1" or "filesha256" option
 * \param type type of file hash to setup
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectFileHashSetup (DetectEngineCtx *de_ctx, Signature *s, char *str,
        uint8_t type)
{
    DetectFileHashData *filehash = NULL;
    SigMatch *sm = NULL;

    filehash = DetectFileHashParse(de_ctx, str, type);
    if (filehash == NULL)
        goto error;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = type;
    sm->ctx = (void *)filehash;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_FILEMATCH);

    if (s->alproto != ALPROTO_HTTP && s->alproto != ALPROTO_SMTP) {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "rule contains conflicting keywords.");
        goto error;
    }

    if (s->alproto == ALPROTO_HTTP) {
        AppLayerHtpNeedFileInspection();
    }

    s->file_flags |= FILE_SIG_NEED_FILE;

    // Setup the file flags depending on the hashing algorithm    
    if (type == DETECT_FILEMD5) {
        s->file_flags |= FILE_SIG_NEED_MD5;
    }
    if (type == DETECT_FILESHA1) {
        s->file_flags |= FILE_SIG_NEED_SHA1;
    }
    if (type == DETECT_FILESHA256) {
        s->file_flags |= FILE_SIG_NEED_SHA256;
    }
    return 0;

error:
    if (filehash != NULL)
        DetectFileHashFree(filehash);
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

static int DetectFileMd5Setup (DetectEngineCtx *de_ctx, Signature *s, char *str)
{
    return DetectFileHashSetup(de_ctx, s, str, DETECT_FILEMD5);
}

static int DetectFileSha1Setup (DetectEngineCtx *de_ctx, Signature *s, char *str)
{
    return DetectFileHashSetup(de_ctx, s, str, DETECT_FILESHA1);
}

static int DetectFileSha256Setup (DetectEngineCtx *de_ctx, Signature *s, char *str)
{
    return DetectFileHashSetup(de_ctx, s, str, DETECT_FILESHA256);
}

/**
 * \brief this function will free memory associated with DetectFileHashData
 *
 * \param filehash pointer to DetectFileHashData
 */
static void DetectFileHashFree(void *ptr)
{
    if (ptr != NULL) {
        DetectFileHashData *filehash = (DetectFileHashData *)ptr;
        if (filehash->hash != NULL)
            ROHashFree(filehash->hash);
        SCFree(filehash);
    }
}

#ifdef UNITTESTS
static int MD5MatchLookupString(ROHashTable *hash_table, char *string)
{
    uint8_t md5[16];
    if (ReadHashString(md5, string, "file", 88, 32) == 1) {
        void *ptr = ROHashLookup(hash_table, &md5, (uint16_t)sizeof(md5));
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
    if (hash == NULL) {
        return 0;
    }
    if (LoadHashTable(hash, "d80f93a93dc5f3ee945704754d6e0a36", "file", 1, DETECT_FILEMD5) != 1)
        return 0;
    if (LoadHashTable(hash, "92a49985b384f0d993a36e4c2d45e206", "file", 2, DETECT_FILEMD5) != 1)
        return 0;
    if (LoadHashTable(hash, "11adeaacc8c309815f7bc3e33888f281", "file", 3, DETECT_FILEMD5) != 1)
        return 0;
    if (LoadHashTable(hash, "22e10a8fe02344ade0bea8836a1714af", "file", 4, DETECT_FILEMD5) != 1)
        return 0;
    if (LoadHashTable(hash, "c3db2cbf02c68f073afcaee5634677bc", "file", 5, DETECT_FILEMD5) != 1)
        return 0;
    if (LoadHashTable(hash, "7ed095da259638f42402fb9e74287a17", "file", 6, DETECT_FILEMD5) != 1)
        return 0;

    if (ROHashInitFinalize(hash) != 1) {
        return 0;
    }

    if (MD5MatchLookupString(hash, "d80f93a93dc5f3ee945704754d6e0a36") != 1)
        return 0;
    if (MD5MatchLookupString(hash, "92a49985b384f0d993a36e4c2d45e206") != 1)
        return 0;
    if (MD5MatchLookupString(hash, "11adeaacc8c309815f7bc3e33888f281") != 1)
        return 0;
    if (MD5MatchLookupString(hash, "22e10a8fe02344ade0bea8836a1714af") != 1)
        return 0;
    if (MD5MatchLookupString(hash, "c3db2cbf02c68f073afcaee5634677bc") != 1)
        return 0;
    if (MD5MatchLookupString(hash, "7ed095da259638f42402fb9e74287a17") != 1)
        return 0;
    /* Shouldn't match */
    if (MD5MatchLookupString(hash, "33333333333333333333333333333333") == 1)
        return 0;

    ROHashFree(hash);
    return 1;
}

static int SHA1MatchLookupString(ROHashTable *hash_table, char *string)
{
    uint8_t sha1[20];
    if (ReadHashString(sha1, string, "file", 88, 40) == 1) {
        void *ptr = ROHashLookup(hash_table, &sha1, (uint16_t)sizeof(sha1));
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

static int SHA256MatchLookupString(ROHashTable *hash_table, char *string)
{
    uint8_t sha256[32];
    if (ReadHashString(sha256, string, "file", 88, 64) == 1) {
        void *ptr = ROHashLookup(hash_table, &sha256, (uint16_t)sizeof(sha256));
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
    if (hash == NULL) {
        return 0;
    }
    if (LoadHashTable(hash, "9c891edb5da763398969b6aaa86a5d46971bd28a455b20c2067cb512c9f9a0f8", "file", 1, DETECT_FILESHA256) != 1)
        return 0;
    if (LoadHashTable(hash, "6eee51705f34b6cfc7f0c872a7949ec3e3172a908303baf5d67d03b98f70e7e3", "file", 2, DETECT_FILESHA256) != 1)
        return 0;
    if (LoadHashTable(hash, "b12c7d57507286bbbe36d7acf9b34c22c96606ffd904e3c23008399a4a50c047", "file", 3, DETECT_FILESHA256) != 1)
        return 0;
    if (LoadHashTable(hash, "ca496e1ddadc290050339dd75ce8830ad3028ce1556a5368874a4aec3aee114b", "file", 4, DETECT_FILESHA256) != 1)
        return 0;
    if (LoadHashTable(hash, "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "file", 5, DETECT_FILESHA256) != 1)
        return 0;
    if (LoadHashTable(hash, "d765e722e295969c0a5c2d90f549db8b89ab617900bf4698db41c7cdad993bb9", "file", 6, DETECT_FILESHA256) != 1)
        return 0;

    if (ROHashInitFinalize(hash) != 1) {
        return 0;
    }

    if (SHA256MatchLookupString(hash, "9c891edb5da763398969b6aaa86a5d46971bd28a455b20c2067cb512c9f9a0f8") != 1)
        return 0;
    if (SHA256MatchLookupString(hash, "6eee51705f34b6cfc7f0c872a7949ec3e3172a908303baf5d67d03b98f70e7e3") != 1)
        return 0;
    if (SHA256MatchLookupString(hash, "b12c7d57507286bbbe36d7acf9b34c22c96606ffd904e3c23008399a4a50c047") != 1)
        return 0;
    if (SHA256MatchLookupString(hash, "ca496e1ddadc290050339dd75ce8830ad3028ce1556a5368874a4aec3aee114b") != 1)
        return 0;
    if (SHA256MatchLookupString(hash, "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f") != 1)
        return 0;
    if (SHA256MatchLookupString(hash, "d765e722e295969c0a5c2d90f549db8b89ab617900bf4698db41c7cdad993bb9") != 1)
        return 0;
    /* Shouldn't match */
    if (SHA256MatchLookupString(hash, "3333333333333333333333333333333333333333333333333333333333333333") == 1)
        return 0;

    ROHashFree(hash);
    return 1;
}
#endif

void DetectFileMd5RegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("MD5MatchTest01", MD5MatchTest01, 1);
#endif
}

void DetectFileSha1RegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("SHA1MatchTest01", SHA1MatchTest01, 1);
#endif
}

void DetectFileSha256RegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("SHA256MatchTest01", SHA256MatchTest01, 1);
#endif
}

#endif /* HAVE_NSS */


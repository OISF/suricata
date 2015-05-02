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

#include "detect-filesha256.h"

#include "queue.h"
#include "util-rohash.h"

#ifndef HAVE_NSS

static int DetectFileSHA256SetupNoSupport (DetectEngineCtx *a, Signature *b, char *c)
{
    SCLogError(SC_ERR_NO_SHA256_SUPPORT, "no SHA256 calculation support built in, needed for filesha256 keyword");
    return -1;
}

/**
 * \brief Registration function for keyword: filesha256
 */
void DetectFileSHA256Register(void)
{
    sigmatch_table[DETECT_FILESHA256].name = "filesha256";
    sigmatch_table[DETECT_FILESHA256].FileMatch = NULL;
    sigmatch_table[DETECT_FILESHA256].alproto = ALPROTO_HTTP;
    sigmatch_table[DETECT_FILESHA256].Setup = DetectFileSHA256SetupNoSupport;
    sigmatch_table[DETECT_FILESHA256].Free  = NULL;
    sigmatch_table[DETECT_FILESHA256].RegisterTests = NULL;
    sigmatch_table[DETECT_FILESHA256].flags = SIGMATCH_NOT_BUILT;

	SCLogDebug("registering filesha256 rule option");
    return;
}

#else /* HAVE_NSS */

static int DetectFileSHA256Match(ThreadVars *, DetectEngineThreadCtx *,
        Flow *, uint8_t, File *, Signature *, SigMatch *);
static int DetectFileSHA256Setup(DetectEngineCtx *, Signature *, char *);
static void DetectFileSHA256RegisterTests(void);
static void DetectFileSHA256Free(void *);

/**
 * \brief Registration function for keyword: filesha256
 */
void DetectFileSHA256Register(void)
{
    sigmatch_table[DETECT_FILESHA256].name = "filesha256";
    sigmatch_table[DETECT_FILESHA256].desc = "match file SHA256 against list of SHA256 checksums";
    sigmatch_table[DETECT_FILESHA256].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/File-keywords#filesha256";
    sigmatch_table[DETECT_FILESHA256].FileMatch = DetectFileSHA256Match;
    sigmatch_table[DETECT_FILESHA256].alproto = ALPROTO_HTTP;
    sigmatch_table[DETECT_FILESHA256].Setup = DetectFileSHA256Setup;
    sigmatch_table[DETECT_FILESHA256].Free  = DetectFileSHA256Free;
    sigmatch_table[DETECT_FILESHA256].RegisterTests = DetectFileSHA256RegisterTests;

	SCLogDebug("registering filesha256 rule option");
    return;
}

static int SHA256ReadString(uint8_t *sha256, char *str, char *filename, int line_no)
{
    if (strlen(str) != 64) {
        SCLogError(SC_ERR_INVALID_SHA256, "%s:%d SHA256 string not 32 bytes",
                filename, line_no);
        return -1;
    }

    int i, x;
    for (x = 0, i = 0; i < 64; i+=2, x++) {
        char buf[3] = { 0, 0, 0};
        buf[0] = str[i];
        buf[1] = str[i+1];

        long value = strtol(buf, NULL, 16);
        if (value >= 0 && value <= 255)
            sha256[x] = (uint8_t)value;
        else {
            SCLogError(SC_ERR_INVALID_SHA256, "%s:%d SHA256 byte out of range %ld",
                    filename, line_no, value);
            return -1;
        }
    }

    return 1;
}

static int SHA256LoadHash(ROHashTable *hash, char *string, char *filename, int line_no)
{
    uint8_t sha256[32];

    if (SHA256ReadString(sha256, string, filename, line_no) == 1) {
        if (ROHashInitQueueValue(hash, &sha256, (uint16_t)sizeof(sha256)) != 1)
            return -1;
    }

    return 1;
}

static int SHA256MatchLookupBuffer(ROHashTable *hash, uint8_t *buf, size_t buflen)
{
    void *ptr = ROHashLookup(hash, buf, (uint16_t)buflen);
    if (ptr == NULL)
        return 0;
    else
        return 1;
}

/**
 * \brief match the specified filesha256
 *
 * \param t thread local vars
 * \param det_ctx pattern matcher thread local data
 * \param f *LOCKED* flow
 * \param flags direction flags
 * \param file file being inspected
 * \param s signature being inspected
 * \param m sigmatch that we will cast into DetectFileSHA256Data
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectFileSHA256Match (ThreadVars *t, DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, File *file, Signature *s, SigMatch *m)
{
    SCEnter();
    int ret = 0;
    DetectFileSHA256Data *filesha256 = (DetectFileSHA256Data *)m->ctx;

    if (file->txid < det_ctx->tx_id) {
        SCReturnInt(0);
    }

    if (file->txid > det_ctx->tx_id) {
        SCReturnInt(0);
    }

    if (file->state != FILE_STATE_CLOSED) {
        SCReturnInt(0);
    }

    if (file->flags & FILE_SHA256) {
        if (SHA256MatchLookupBuffer(filesha256->hash, file->sha256, sizeof(file->sha256)) == 1) {
            if (filesha256->negated == 0)
                ret = 1;
            else
                ret = 0;
        } else {
            if (filesha256->negated == 0)
                ret = 0;
            else
                ret = 1;
        }
    }

    SCReturnInt(ret);
}

/**
 * \brief Parse the filesha256 keyword
 *
 * \param idstr Pointer to the user provided option
 *
 * \retval filesha256 pointer to DetectFileSHA256Data on success
 * \retval NULL on failure
 */
static DetectFileSHA256Data *DetectFileSHA256Parse (char *str)
{
    DetectFileSHA256Data *filesha256 = NULL;
    FILE *fp = NULL;
    char *filename = NULL;

    /* We have a correct filesha256 option */
    filesha256 = SCMalloc(sizeof(DetectFileSHA256Data));
    if (unlikely(filesha256 == NULL))
        goto error;

    memset(filesha256, 0x00, sizeof(DetectFileSHA256Data));

    if (strlen(str) && str[0] == '!') {
        filesha256->negated = 1;
        str++;
    }

    filesha256->hash = ROHashInit(18, 16);
    if (filesha256->hash == NULL) {
        goto error;
    }

    /* get full filename */
    filename = DetectLoadCompleteSigPath(str);
    if (filename == NULL) {
        goto error;
    }

    char line[8192] = "";
    fp = fopen(filename, "r");
    if (fp == NULL) {
        SCLogError(SC_ERR_OPENING_RULE_FILE, "opening SHA256 file %s: %s", filename, strerror(errno));
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

        /* cut off longer lines */
        if (strlen(line) > 64)
            line[64] = 0x00;

        if (SHA256LoadHash(filesha256->hash, line, filename, line_no) != 1) {
            goto error;
        }
    }
    fclose(fp);
    fp = NULL;

    if (ROHashInitFinalize(filesha256->hash) != 1) {
        goto error;
    }
    SCLogInfo("SHA256 hash size %u bytes%s", ROHashMemorySize(filesha256->hash), filesha256->negated ? ", negated match" : "");

    SCFree(filename);
    return filesha256;

error:
    if (filesha256 != NULL)
        DetectFileSHA256Free(filesha256);
    if (fp != NULL)
        fclose(fp);
    if (filename != NULL)
        SCFree(filename);
    return NULL;
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
static int DetectFileSHA256Setup (DetectEngineCtx *de_ctx, Signature *s, char *str)
{
    DetectFileSHA256Data *filesha256 = NULL;
    SigMatch *sm = NULL;

    filesha256 = DetectFileSHA256Parse(str);
    if (filesha256 == NULL)
        goto error;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_FILESHA256;
    sm->ctx = (void *)filesha256;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_FILEMATCH);

    if (s->alproto != ALPROTO_HTTP && s->alproto != ALPROTO_SMTP) {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "rule contains conflicting keywords.");
        goto error;
    }

    if (s->alproto == ALPROTO_HTTP) {
        AppLayerHtpNeedFileInspection();
    }

    s->file_flags |= (FILE_SIG_NEED_FILE|FILE_SIG_NEED_SHA256);
    return 0;

error:
    if (filesha256 != NULL)
        DetectFileSHA256Free(filesha256);
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

/**
 * \brief this function will free memory associated with DetectFileSHA256Data
 *
 * \param filesha256 pointer to DetectFileSHA256Data
 */
static void DetectFileSHA256Free(void *ptr)
{
    if (ptr != NULL) {
        DetectFileSHA256Data *filesha256 = (DetectFileSHA256Data *)ptr;
        if (filesha256->hash != NULL)
            ROHashFree(filesha256->hash);
        SCFree(filesha256);
    }
}

#ifdef UNITTESTS
static int SHA256MatchLookupString(ROHashTable *hash, char *string)
{
    uint8_t sha256[32];
    if (SHA256ReadString(sha256, string, "file", 88) == 1) {
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
    if (hash == NULL) {
        return 0;
    }
    if (SHA256LoadHash(hash, "9c891edb5da763398969b6aaa86a5d46971bd28a455b20c2067cb512c9f9a0f8", "file", 1) != 1)
        return 0;
    if (SHA256LoadHash(hash, "6eee51705f34b6cfc7f0c872a7949ec3e3172a908303baf5d67d03b98f70e7e3", "file", 2) != 1)
        return 0;
    if (SHA256LoadHash(hash, "b12c7d57507286bbbe36d7acf9b34c22c96606ffd904e3c23008399a4a50c047", "file", 3) != 1)
        return 0;
    if (SHA256LoadHash(hash, "ca496e1ddadc290050339dd75ce8830ad3028ce1556a5368874a4aec3aee114b", "file", 4) != 1)
        return 0;
    if (SHA256LoadHash(hash, "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f", "file", 5) != 1)
        return 0;
    if (SHA256LoadHash(hash, "d765e722e295969c0a5c2d90f549db8b89ab617900bf4698db41c7cdad993bb9", "file", 6) != 1)
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
    /* shouldnt match */
    if (SHA256MatchLookupString(hash, "3333333333333333333333333333333333333333333333333333333333333333") == 1)
        return 0;

    ROHashFree(hash);
    return 1;
}
#endif

void DetectFileSHA256RegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("SHA256MatchTest01", SHA256MatchTest01, 1);
#endif
}

#endif /* HAVE_NSS */


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

#include "detect-filemd5.h"

#include "queue.h"
#include "util-rohash.h"

#ifndef HAVE_NSS

static int DetectFileMd5SetupNoSupport (DetectEngineCtx *a, Signature *b, char *c)
{
    SCLogError(SC_ERR_NO_MD5_SUPPORT, "no MD5 calculation support built in, needed for filemd5 keyword");
    return -1;
}

/**
 * \brief Registration function for keyword: filemd5
 */
void DetectFileMd5Register(void)
{
    sigmatch_table[DETECT_FILEMD5].name = "filemd5";
    sigmatch_table[DETECT_FILEMD5].FileMatch = NULL;
    sigmatch_table[DETECT_FILEMD5].alproto = ALPROTO_HTTP;
    sigmatch_table[DETECT_FILEMD5].Setup = DetectFileMd5SetupNoSupport;
    sigmatch_table[DETECT_FILEMD5].Free  = NULL;
    sigmatch_table[DETECT_FILEMD5].RegisterTests = NULL;
    sigmatch_table[DETECT_FILEMD5].flags = SIGMATCH_NOT_BUILT;

	SCLogDebug("registering filemd5 rule option");
    return;
}

#else /* HAVE_NSS */

static int DetectFileMd5Match (ThreadVars *, DetectEngineThreadCtx *,
        Flow *, uint8_t, File *, Signature *, SigMatch *);
static int DetectFileMd5Setup (DetectEngineCtx *, Signature *, char *);
static void DetectFileMd5RegisterTests(void);
static void DetectFileMd5Free(void *);

/**
 * \brief Registration function for keyword: filemd5
 */
void DetectFileMd5Register(void)
{
    sigmatch_table[DETECT_FILEMD5].name = "filemd5";
    sigmatch_table[DETECT_FILEMD5].desc = "match file MD5 against list of MD5 checksums";
    sigmatch_table[DETECT_FILEMD5].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/File-keywords#filemd5";
    sigmatch_table[DETECT_FILEMD5].FileMatch = DetectFileMd5Match;
    sigmatch_table[DETECT_FILEMD5].alproto = ALPROTO_HTTP;
    sigmatch_table[DETECT_FILEMD5].Setup = DetectFileMd5Setup;
    sigmatch_table[DETECT_FILEMD5].Free  = DetectFileMd5Free;
    sigmatch_table[DETECT_FILEMD5].RegisterTests = DetectFileMd5RegisterTests;

	SCLogDebug("registering filemd5 rule option");
    return;
}

static int Md5ReadString(uint8_t *md5, char *str, char *filename, int line_no)
{
    if (strlen(str) != 32) {
        SCLogError(SC_ERR_INVALID_MD5, "%s:%d md5 string not 32 bytes",
                filename, line_no);
        return -1;
    }

    int i, x;
    for (x = 0, i = 0; i < 32; i+=2, x++) {
        char buf[3] = { 0, 0, 0};
        buf[0] = str[i];
        buf[1] = str[i+1];

        long value = strtol(buf, NULL, 16);
        if (value >= 0 && value <= 255)
            md5[x] = (uint8_t)value;
        else {
            SCLogError(SC_ERR_INVALID_MD5, "%s:%d md5 byte out of range %ld",
                    filename, line_no, value);
            return -1;
        }
    }

    return 1;
}

static int MD5LoadHash(ROHashTable *hash, char *string, char *filename, int line_no)
{
    uint8_t md5[16];

    if (Md5ReadString(md5, string, filename, line_no) == 1) {
        if (ROHashInitQueueValue(hash, &md5, (uint16_t)sizeof(md5)) != 1)
            return -1;
    }

    return 1;
}

static int MD5MatchLookupBuffer(ROHashTable *hash, uint8_t *buf, size_t buflen)
{
    void *ptr = ROHashLookup(hash, buf, (uint16_t)buflen);
    if (ptr == NULL)
        return 0;
    else
        return 1;
}

/**
 * \brief match the specified filemd5
 *
 * \param t thread local vars
 * \param det_ctx pattern matcher thread local data
 * \param f *LOCKED* flow
 * \param flags direction flags
 * \param file file being inspected
 * \param s signature being inspected
 * \param m sigmatch that we will cast into DetectFileMd5Data
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectFileMd5Match (ThreadVars *t, DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, File *file, Signature *s, SigMatch *m)
{
    SCEnter();
    int ret = 0;
    DetectFileMd5Data *filemd5 = (DetectFileMd5Data *)m->ctx;

    if (file->txid < det_ctx->tx_id) {
        SCReturnInt(0);
    }

    if (file->txid > det_ctx->tx_id) {
        SCReturnInt(0);
    }

    if (file->state != FILE_STATE_CLOSED) {
        SCReturnInt(0);
    }

    if (file->flags & FILE_MD5) {
        if (MD5MatchLookupBuffer(filemd5->hash, file->md5, sizeof(file->md5)) == 1) {
            if (filemd5->negated == 0)
                ret = 1;
            else
                ret = 0;
        } else {
            if (filemd5->negated == 0)
                ret = 0;
            else
                ret = 1;
        }
    }

    SCReturnInt(ret);
}

/**
 * \brief Parse the filemd5 keyword
 *
 * \param idstr Pointer to the user provided option
 *
 * \retval filemd5 pointer to DetectFileMd5Data on success
 * \retval NULL on failure
 */
static DetectFileMd5Data *DetectFileMd5Parse (const DetectEngineCtx *de_ctx, char *str)
{
    DetectFileMd5Data *filemd5 = NULL;
    FILE *fp = NULL;
    char *filename = NULL;

    /* We have a correct filemd5 option */
    filemd5 = SCMalloc(sizeof(DetectFileMd5Data));
    if (unlikely(filemd5 == NULL))
        goto error;

    memset(filemd5, 0x00, sizeof(DetectFileMd5Data));

    if (strlen(str) && str[0] == '!') {
        filemd5->negated = 1;
        str++;
    }

    filemd5->hash = ROHashInit(18, 16);
    if (filemd5->hash == NULL) {
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
        SCLogError(SC_ERR_OPENING_RULE_FILE, "opening md5 file %s: %s", filename, strerror(errno));
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
        if (strlen(line) > 32)
            line[32] = 0x00;

        if (MD5LoadHash(filemd5->hash, line, filename, line_no) != 1) {
            goto error;
        }
    }
    fclose(fp);
    fp = NULL;

    if (ROHashInitFinalize(filemd5->hash) != 1) {
        goto error;
    }
    SCLogInfo("MD5 hash size %u bytes%s", ROHashMemorySize(filemd5->hash), filemd5->negated ? ", negated match" : "");

    SCFree(filename);
    return filemd5;

error:
    if (filemd5 != NULL)
        DetectFileMd5Free(filemd5);
    if (fp != NULL)
        fclose(fp);
    if (filename != NULL)
        SCFree(filename);
    return NULL;
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
static int DetectFileMd5Setup (DetectEngineCtx *de_ctx, Signature *s, char *str)
{
    DetectFileMd5Data *filemd5 = NULL;
    SigMatch *sm = NULL;

    filemd5 = DetectFileMd5Parse(de_ctx, str);
    if (filemd5 == NULL)
        goto error;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_FILEMD5;
    sm->ctx = (void *)filemd5;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_FILEMATCH);

    if (s->alproto != ALPROTO_HTTP && s->alproto != ALPROTO_SMTP) {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "rule contains conflicting keywords.");
        goto error;
    }

    if (s->alproto == ALPROTO_HTTP) {
        AppLayerHtpNeedFileInspection();
    }

    s->file_flags |= (FILE_SIG_NEED_FILE|FILE_SIG_NEED_MD5);
    return 0;

error:
    if (filemd5 != NULL)
        DetectFileMd5Free(filemd5);
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

/**
 * \brief this function will free memory associated with DetectFileMd5Data
 *
 * \param filemd5 pointer to DetectFileMd5Data
 */
static void DetectFileMd5Free(void *ptr)
{
    if (ptr != NULL) {
        DetectFileMd5Data *filemd5 = (DetectFileMd5Data *)ptr;
        if (filemd5->hash != NULL)
            ROHashFree(filemd5->hash);
        SCFree(filemd5);
    }
}

#ifdef UNITTESTS
static int MD5MatchLookupString(ROHashTable *hash, char *string)
{
    uint8_t md5[16];
    if (Md5ReadString(md5, string, "file", 88) == 1) {
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
    if (hash == NULL) {
        return 0;
    }
    if (MD5LoadHash(hash, "d80f93a93dc5f3ee945704754d6e0a36", "file", 1) != 1)
        return 0;
    if (MD5LoadHash(hash, "92a49985b384f0d993a36e4c2d45e206", "file", 2) != 1)
        return 0;
    if (MD5LoadHash(hash, "11adeaacc8c309815f7bc3e33888f281", "file", 3) != 1)
        return 0;
    if (MD5LoadHash(hash, "22e10a8fe02344ade0bea8836a1714af", "file", 4) != 1)
        return 0;
    if (MD5LoadHash(hash, "c3db2cbf02c68f073afcaee5634677bc", "file", 5) != 1)
        return 0;
    if (MD5LoadHash(hash, "7ed095da259638f42402fb9e74287a17", "file", 6) != 1)
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
    /* shouldnt match */
    if (MD5MatchLookupString(hash, "33333333333333333333333333333333") == 1)
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

#endif /* HAVE_NSS */


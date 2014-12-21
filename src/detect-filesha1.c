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

#include "detect-filesha1.h"

#include "queue.h"
#include "util-rohash.h"

#ifndef HAVE_NSS

static int DetectFileSHA1SetupNoSupport(DetectEngineCtx *a, Signature *b, char *c)
{
    SCLogError(SC_ERR_NO_SHA1_SUPPORT, "no SHA1 calculation support built in, needed for filesha1 keyword");
    return -1;
}

/**
 * \brief Registration function for keyword: filesha1
 */
void DetectFileSHA1Register(void)
{
    sigmatch_table[DETECT_FILESHA1].name = "filesha1";
    sigmatch_table[DETECT_FILESHA1].FileMatch = NULL;
    sigmatch_table[DETECT_FILESHA1].alproto = ALPROTO_HTTP;
    sigmatch_table[DETECT_FILESHA1].Setup = DetectFileSHA1SetupNoSupport;
    sigmatch_table[DETECT_FILESHA1].Free  = NULL;
    sigmatch_table[DETECT_FILESHA1].RegisterTests = NULL;
    sigmatch_table[DETECT_FILESHA1].flags = SIGMATCH_NOT_BUILT;

	SCLogDebug("registering filesha1 rule option");
    return;
}

#else /* HAVE_NSS */

static int DetectFileSHA1Match(ThreadVars *, DetectEngineThreadCtx *,
        Flow *, uint8_t, File *, Signature *, SigMatch *);
static int DetectFileSHA1Setup(DetectEngineCtx *, Signature *, char *);
static void DetectFileSHA1RegisterTests(void);
static void DetectFileSHA1Free(void *);

/**
 * \brief Registration function for keyword: filesha1
 */
void DetectFileSHA1Register(void)
{
    sigmatch_table[DETECT_FILESHA1].name = "filesha1";
    sigmatch_table[DETECT_FILESHA1].desc = "match file SHA1 against list of SHA1 checksums";
    sigmatch_table[DETECT_FILESHA1].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/File-keywords#filesha1";
    sigmatch_table[DETECT_FILESHA1].FileMatch = DetectFileSHA1Match;
    sigmatch_table[DETECT_FILESHA1].alproto = ALPROTO_HTTP;
    sigmatch_table[DETECT_FILESHA1].Setup = DetectFileSHA1Setup;
    sigmatch_table[DETECT_FILESHA1].Free  = DetectFileSHA1Free;
    sigmatch_table[DETECT_FILESHA1].RegisterTests = DetectFileSHA1RegisterTests;

	SCLogDebug("registering filesha1 rule option");
    return;
}

static int SHA1ReadString(uint8_t *sha1, char *str, char *filename, int line_no)
{
    if (strlen(str) != 40) {
        SCLogError(SC_ERR_INVALID_SHA1, "%s:%d SHA1 string not 20 bytes",
                filename, line_no);
        return -1;
    }

    int i, x;
    for (x = 0, i = 0; i < 40; i+=2, x++) {
        char buf[3] = { 0, 0, 0};
        buf[0] = str[i];
        buf[1] = str[i+1];

        long value = strtol(buf, NULL, 16);
        if (value >= 0 && value <= 255)
            sha1[x] = (uint8_t)value;
        else {
            SCLogError(SC_ERR_INVALID_SHA1, "%s:%d SHA1 byte out of range %ld",
                    filename, line_no, value);
            return -1;
        }
    }

    return 1;
}

static int SHA1LoadHash(ROHashTable *hash, char *string, char *filename, int line_no)
{
    uint8_t sha1[20];

    if (SHA1ReadString(sha1, string, filename, line_no) == 1) {
        if (ROHashInitQueueValue(hash, &sha1, (uint16_t)sizeof(sha1)) != 1)
            return -1;
    }

    return 1;
}

static int SHA1MatchLookupBuffer(ROHashTable *hash, uint8_t *buf, size_t buflen)
{
    void *ptr = ROHashLookup(hash, buf, (uint16_t)buflen);
    if (ptr == NULL)
        return 0;
    else
        return 1;
}

/**
 * \brief match the specified filesha1
 *
 * \param t thread local vars
 * \param det_ctx pattern matcher thread local data
 * \param f *LOCKED* flow
 * \param flags direction flags
 * \param file file being inspected
 * \param s signature being inspected
 * \param m sigmatch that we will cast into DetectFileSHA1Data
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectFileSHA1Match (ThreadVars *t, DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, File *file, Signature *s, SigMatch *m)
{
    SCEnter();
    int ret = 0;
    DetectFileSHA1Data *filesha1 = (DetectFileSHA1Data *)m->ctx;

    if (file->txid < det_ctx->tx_id) {
        SCReturnInt(0);
    }

    if (file->txid > det_ctx->tx_id) {
        SCReturnInt(0);
    }

    if (file->state != FILE_STATE_CLOSED) {
        SCReturnInt(0);
    }

    if (file->flags & FILE_SHA1) {
        if (SHA1MatchLookupBuffer(filesha1->hash, file->sha1, sizeof(file->sha1)) == 1) {
            if (filesha1->negated == 0)
                ret = 1;
            else
                ret = 0;
        } else {
            if (filesha1->negated == 0)
                ret = 0;
            else
                ret = 1;
        }
    }

    SCReturnInt(ret);
}

/**
 * \brief Parse the filesha1 keyword
 *
 * \param idstr Pointer to the user provided option
 *
 * \retval filesha1 pointer to DetectFileSHA1Data on success
 * \retval NULL on failure
 */
static DetectFileSHA1Data *DetectFileSHA1Parse(char *str)
{
    DetectFileSHA1Data *filesha1 = NULL;
    FILE *fp = NULL;
    char *filename = NULL;

    /* We have a correct filesha1 option */
    filesha1 = SCMalloc(sizeof(DetectFileSHA1Data));
    if (unlikely(filesha1 == NULL))
        goto error;

    memset(filesha1, 0x00, sizeof(DetectFileSHA1Data));

    if (strlen(str) && str[0] == '!') {
        filesha1->negated = 1;
        str++;
    }

    filesha1->hash = ROHashInit(18, 20);
    if (filesha1->hash == NULL) {
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
        SCLogError(SC_ERR_OPENING_RULE_FILE, "opening SHA1 file %s: %s", filename, strerror(errno));
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
        if (strlen(line) > 40)
            line[40] = 0x00;

        if (SHA1LoadHash(filesha1->hash, line, filename, line_no) != 1) {
            goto error;
        }
    }
    fclose(fp);
    fp = NULL;

    if (ROHashInitFinalize(filesha1->hash) != 1) {
        goto error;
    }
    SCLogInfo("SHA1 hash size %u bytes%s", ROHashMemorySize(filesha1->hash), filesha1->negated ? ", negated match" : "");

    SCFree(filename);
    return filesha1;

error:
    if (filesha1 != NULL)
        DetectFileSHA1Free(filesha1);
    if (fp != NULL)
        fclose(fp);
    if (filename != NULL)
        SCFree(filename);
    return NULL;
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
static int DetectFileSHA1Setup (DetectEngineCtx *de_ctx, Signature *s, char *str)
{
    DetectFileSHA1Data *filesha1 = NULL;
    SigMatch *sm = NULL;

    filesha1 = DetectFileSHA1Parse(str);
    if (filesha1 == NULL)
        goto error;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_FILESHA1;
    sm->ctx = (void *)filesha1;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_FILEMATCH);

    if (s->alproto != ALPROTO_HTTP && s->alproto != ALPROTO_SMTP) {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "rule contains conflicting keywords.");
        goto error;
    }

    if (s->alproto == ALPROTO_HTTP) {
        AppLayerHtpNeedFileInspection();
    }

    s->file_flags |= (FILE_SIG_NEED_FILE|FILE_SIG_NEED_SHA1);
    return 0;

error:
    if (filesha1 != NULL)
        DetectFileSHA1Free(filesha1);
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

/**
 * \brief this function will free memory associated with DetectFileSHA1Data
 *
 * \param filesha1 pointer to DetectFileSHA1Data
 */
static void DetectFileSHA1Free(void *ptr)
{
    if (ptr != NULL) {
        DetectFileSHA1Data *filesha1 = (DetectFileSHA1Data *)ptr;
        if (filesha1->hash != NULL)
            ROHashFree(filesha1->hash);
        SCFree(filesha1);
    }
}

#ifdef UNITTESTS
static int SHA1MatchLookupString(ROHashTable *hash, char *string)
{
    uint8_t sha1[20];
    if (SHA1ReadString(sha1, string, "file", 88) == 1) {
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
    if (SHA1LoadHash(hash, "447661c5de965bd4d837b50244467e37bddc184d", "file", 1) != 1)
        return 0;
    if (SHA1LoadHash(hash, "75a9af1e34dc0bb2f7fcde9d56b2503072ac35dd", "file", 2) != 1)
        return 0;
    if (SHA1LoadHash(hash, "53224a297bbb30631670fdcd2d295d87a1d328e9", "file", 3) != 1)
        return 0;
    if (SHA1LoadHash(hash, "3395856ce81f2b7382dee72602f798b642f14140", "file", 4) != 1)
        return 0;
    if (SHA1LoadHash(hash, "65559245709fe98052eb284577f1fd61c01ad20d", "file", 5) != 1)
        return 0;
    if (SHA1LoadHash(hash, "0931fd4e05e6ea81c75f8488ecc1db9e66f22cbb", "file", 6) != 1)
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
    /* shouldnt match */
    if (SHA1MatchLookupString(hash, "3333333333333333333333333333333333333333") == 1)
        return 0;

    ROHashFree(hash);
    return 1;
}
#endif

void DetectFileSHA1RegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("SHA1MatchTest01", SHA1MatchTest01, 1);
#endif
}

#endif /* HAVE_NSS */

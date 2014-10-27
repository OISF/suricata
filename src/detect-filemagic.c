/* Copyright (C) 2007-2014 Open Information Security Foundation
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
#include "util-magic.h"
#include "util-print.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "app-layer.h"

#include "stream-tcp.h"

#include "detect-filemagic.h"

#include "conf.h"
#include "util-magic.h"

static int DetectFilemagicMatch (ThreadVars *, DetectEngineThreadCtx *, Flow *,
        uint8_t, File *, Signature *, SigMatch *);
static int DetectFilemagicSetup (DetectEngineCtx *, Signature *, char *);
static void DetectFilemagicRegisterTests(void);
static void DetectFilemagicFree(void *);

/**
 * \brief Registration function for keyword: filemagic
 */
void DetectFilemagicRegister(void)
{
    sigmatch_table[DETECT_FILEMAGIC].name = "filemagic";
    sigmatch_table[DETECT_FILEMAGIC].desc = "match on the information libmagic returns about a file";
    sigmatch_table[DETECT_FILEMAGIC].url = "https://redmine.openinfosecfoundation.org/projects/suricata/wiki/File-keywords#filemagic";
    sigmatch_table[DETECT_FILEMAGIC].FileMatch = DetectFilemagicMatch;
    sigmatch_table[DETECT_FILEMAGIC].alproto = ALPROTO_HTTP;
    sigmatch_table[DETECT_FILEMAGIC].Setup = DetectFilemagicSetup;
    sigmatch_table[DETECT_FILEMAGIC].Free  = DetectFilemagicFree;
    sigmatch_table[DETECT_FILEMAGIC].RegisterTests = DetectFilemagicRegisterTests;

	SCLogDebug("registering filemagic rule option");
    return;
}

#define FILEMAGIC_MIN_SIZE  512

/**
 *  \brief run the magic check
 *
 *  \param file the file
 *
 *  \retval -1 error
 *  \retval 0 ok
 */
int FilemagicGlobalLookup(File *file)
{
    if (file == NULL || file->chunks_head == NULL) {
        SCReturnInt(-1);
    }

    /* initial chunk already matching our requirement */
    if (file->chunks_head->len >= FILEMAGIC_MIN_SIZE) {
        file->magic = MagicGlobalLookup(file->chunks_head->data, FILEMAGIC_MIN_SIZE);
    } else {
        uint8_t *buf = SCMalloc(FILEMAGIC_MIN_SIZE);
        uint32_t size = 0;

        if (likely(buf != NULL)) {
            FileData *ffd = file->chunks_head;

            for ( ; ffd != NULL; ffd = ffd->next) {
                uint32_t copy_len = ffd->len;
                if (size + ffd->len > FILEMAGIC_MIN_SIZE)
                    copy_len = FILEMAGIC_MIN_SIZE - size;

                memcpy(buf + size, ffd->data, copy_len);
                size += copy_len;

                if (size >= FILEMAGIC_MIN_SIZE) {
                    file->magic = MagicGlobalLookup(buf, size);
                    break;
                }
                /* file is done but smaller than FILEMAGIC_MIN_SIZE */
                if (ffd->next == NULL && file->state >= FILE_STATE_CLOSED) {
                    file->magic = MagicGlobalLookup(buf, size);
                    break;
                }
            }

            SCFree(buf);
        }
    }

    SCReturnInt(0);
}

/**
 *  \brief run the magic check
 *
 *  \param file the file
 *
 *  \retval -1 error
 *  \retval 0 ok
 */
int FilemagicThreadLookup(magic_t *ctx, File *file)
{
    if (ctx == NULL || file == NULL || file->chunks_head == NULL) {
        SCReturnInt(-1);
    }

    /* initial chunk already matching our requirement */
    if (file->chunks_head->len >= FILEMAGIC_MIN_SIZE) {
        file->magic = MagicThreadLookup(ctx, file->chunks_head->data, FILEMAGIC_MIN_SIZE);
    } else {
        uint8_t *buf = SCMalloc(FILEMAGIC_MIN_SIZE);
        uint32_t size = 0;

        if (likely(buf != NULL)) {
            FileData *ffd = file->chunks_head;

            for ( ; ffd != NULL; ffd = ffd->next) {
                uint32_t copy_len = ffd->len;
                if (size + ffd->len > FILEMAGIC_MIN_SIZE)
                    copy_len = FILEMAGIC_MIN_SIZE - size;

                memcpy(buf + size, ffd->data, copy_len);
                size += copy_len;

                if (size >= FILEMAGIC_MIN_SIZE) {
                    file->magic = MagicThreadLookup(ctx, buf, size);
                    break;
                }
                /* file is done but smaller than FILEMAGIC_MIN_SIZE */
                if (ffd->next == NULL && file->state >= FILE_STATE_CLOSED) {
                    file->magic = MagicThreadLookup(ctx, buf, size);
                    break;
                }
            }

            SCFree(buf);
        }
    }

    SCReturnInt(0);
}

/**
 * \brief match the specified filemagic
 *
 * \param t thread local vars
 * \param det_ctx pattern matcher thread local data
 * \param f *LOCKED* flow
 * \param flags direction flags
 * \param file file being inspected
 * \param s signature being inspected
 * \param m sigmatch that we will cast into DetectFilemagicData
 *
 * \retval 0 no match
 * \retval 1 match
 */
static int DetectFilemagicMatch (ThreadVars *t, DetectEngineThreadCtx *det_ctx,
        Flow *f, uint8_t flags, File *file, Signature *s, SigMatch *m)
{
    SCEnter();
    int ret = 0;
    DetectFilemagicData *filemagic = (DetectFilemagicData *)m->ctx;

    if (file->txid < det_ctx->tx_id)
        SCReturnInt(0);

    if (file->txid > det_ctx->tx_id)
        SCReturnInt(0);

    DetectFilemagicThreadData *tfilemagic = (DetectFilemagicThreadData *)DetectThreadCtxGetKeywordThreadCtx(det_ctx, filemagic->thread_ctx_id);
    if (tfilemagic == NULL) {
        SCReturnInt(0);
    }

    if (file->magic == NULL) {
        FilemagicThreadLookup(&tfilemagic->ctx, file);
    }

    if (file->magic != NULL) {
        SCLogDebug("magic %s", file->magic);

        /* we include the \0 in the inspection, so patterns can match on the
         * end of the string. */
        if (BoyerMooreNocase(filemagic->name, filemagic->len, (uint8_t *)file->magic,
                    strlen(file->magic) + 1, filemagic->bm_ctx) != NULL)
        {
#ifdef DEBUG
            if (SCLogDebugEnabled()) {
                char *name = SCMalloc(filemagic->len + 1);
                if (name != NULL) {
                    memcpy(name, filemagic->name, filemagic->len);
                    name[filemagic->len] = '\0';
                    SCLogDebug("will look for filemagic %s", name);
                }
            }
#endif

            if (!(filemagic->flags & DETECT_CONTENT_NEGATED)) {
                ret = 1;
            }
        } else if (filemagic->flags & DETECT_CONTENT_NEGATED) {
            SCLogDebug("negated match");
            ret = 1;
        }
    }

    SCReturnInt(ret);
}

/**
 * \brief Parse the filemagic keyword
 *
 * \param idstr Pointer to the user provided option
 *
 * \retval filemagic pointer to DetectFilemagicData on success
 * \retval NULL on failure
 */
static DetectFilemagicData *DetectFilemagicParse (char *str)
{
    DetectFilemagicData *filemagic = NULL;

    /* We have a correct filemagic option */
    filemagic = SCMalloc(sizeof(DetectFilemagicData));
    if (unlikely(filemagic == NULL))
        goto error;

    memset(filemagic, 0x00, sizeof(DetectFilemagicData));

    if (DetectContentDataParse ("filemagic", str, &filemagic->name, &filemagic->len, &filemagic->flags) == -1) {
        goto error;
    }

    filemagic->bm_ctx = BoyerMooreNocaseCtxInit(filemagic->name, filemagic->len);
    if (filemagic->bm_ctx == NULL) {
        goto error;
    }

    SCLogDebug("flags %02X", filemagic->flags);
    if (filemagic->flags & DETECT_CONTENT_NEGATED) {
        SCLogDebug("negated filemagic");
    }

#ifdef DEBUG
    if (SCLogDebugEnabled()) {
        char *name = SCMalloc(filemagic->len + 1);
        if (name != NULL) {
            memcpy(name, filemagic->name, filemagic->len);
            name[filemagic->len] = '\0';
            SCLogDebug("will look for filemagic %s", name);
        }
    }
#endif

    return filemagic;

error:
    if (filemagic != NULL)
        DetectFilemagicFree(filemagic);
    return NULL;
}

static void *DetectFilemagicThreadInit(void *data)
{
    char *filename = NULL;
    FILE *fd = NULL;
    DetectFilemagicData *filemagic = (DetectFilemagicData *)data;
    BUG_ON(filemagic == NULL);

    DetectFilemagicThreadData *t = SCMalloc(sizeof(DetectFilemagicThreadData));
    if (unlikely(t == NULL)) {
        SCLogError(SC_ERR_MEM_ALLOC, "couldn't alloc ctx memory");
        return NULL;
    }
    memset(t, 0x00, sizeof(DetectFilemagicThreadData));

    t->ctx = magic_open(0);
    if (t->ctx == NULL) {
        SCLogError(SC_ERR_MAGIC_OPEN, "magic_open failed: %s", magic_error(t->ctx));
        goto error;
    }

    (void)ConfGet("magic-file", &filename);
    if (filename != NULL) {
        SCLogInfo("using magic-file %s", filename);

        if ( (fd = fopen(filename, "r")) == NULL) {
            SCLogWarning(SC_ERR_FOPEN, "Error opening file: \"%s\": %s", filename, strerror(errno));
            goto error;
        }
        fclose(fd);
    }

    if (magic_load(t->ctx, filename) != 0) {
        SCLogError(SC_ERR_MAGIC_LOAD, "magic_load failed: %s", magic_error(t->ctx));
        goto error;
    }

    return (void *)t;

error:
    if (t->ctx)
        magic_close(t->ctx);
    SCFree(t);
    return NULL;
}

static void DetectFilemagicThreadFree(void *ctx)
{
    if (ctx != NULL) {
        DetectFilemagicThreadData *t = (DetectFilemagicThreadData *)ctx;
        if (t->ctx)
            magic_close(t->ctx);
        SCFree(t);
    }
}

/**
 * \brief this function is used to parse filemagic options
 * \brief into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param str pointer to the user provided "filemagic" option
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectFilemagicSetup (DetectEngineCtx *de_ctx, Signature *s, char *str)
{
    DetectFilemagicData *filemagic = NULL;
    SigMatch *sm = NULL;

    filemagic = DetectFilemagicParse(str);
    if (filemagic == NULL)
        goto error;

    filemagic->thread_ctx_id = DetectRegisterThreadCtxFuncs(de_ctx, "filemagic",
            DetectFilemagicThreadInit, (void *)filemagic,
            DetectFilemagicThreadFree, 1);
    if (filemagic->thread_ctx_id == -1)
        goto error;

    /* Okay so far so good, lets get this into a SigMatch
     * and put it in the Signature. */
    sm = SigMatchAlloc();
    if (sm == NULL)
        goto error;

    sm->type = DETECT_FILEMAGIC;
    sm->ctx = (void *)filemagic;

    SigMatchAppendSMToList(s, sm, DETECT_SM_LIST_FILEMATCH);

    if (s->alproto != ALPROTO_HTTP && s->alproto != ALPROTO_SMTP) {
        SCLogError(SC_ERR_CONFLICTING_RULE_KEYWORDS, "rule contains conflicting keywords.");
        goto error;
    }

    if (s->alproto == ALPROTO_HTTP) {
        AppLayerHtpNeedFileInspection();
    }

    s->file_flags |= (FILE_SIG_NEED_FILE|FILE_SIG_NEED_MAGIC);
    return 0;

error:
    if (filemagic != NULL)
        DetectFilemagicFree(filemagic);
    if (sm != NULL)
        SCFree(sm);
    return -1;
}

/**
 * \brief this function will free memory associated with DetectFilemagicData
 *
 * \param filemagic pointer to DetectFilemagicData
 */
static void DetectFilemagicFree(void *ptr)
{
    if (ptr != NULL) {
        DetectFilemagicData *filemagic = (DetectFilemagicData *)ptr;
        if (filemagic->bm_ctx != NULL) {
            BoyerMooreCtxDeInit(filemagic->bm_ctx);
        }
        if (filemagic->name != NULL)
            SCFree(filemagic->name);
        SCFree(filemagic);
    }
}

#ifdef UNITTESTS /* UNITTESTS */

/**
 * \test DetectFilemagicTestParse01
 */
int DetectFilemagicTestParse01 (void)
{
    DetectFilemagicData *dnd = DetectFilemagicParse("\"secret.pdf\"");
    if (dnd != NULL) {
        DetectFilemagicFree(dnd);
        return 1;
    }
    return 0;
}

/**
 * \test DetectFilemagicTestParse02
 */
int DetectFilemagicTestParse02 (void)
{
    int result = 0;

    DetectFilemagicData *dnd = DetectFilemagicParse("\"backup.tar.gz\"");
    if (dnd != NULL) {
        if (dnd->len == 13 && memcmp(dnd->name, "backup.tar.gz", 13) == 0) {
            result = 1;
        }

        DetectFilemagicFree(dnd);
        return result;
    }
    return 0;
}

/**
 * \test DetectFilemagicTestParse03
 */
int DetectFilemagicTestParse03 (void)
{
    int result = 0;

    DetectFilemagicData *dnd = DetectFilemagicParse("\"cmd.exe\"");
    if (dnd != NULL) {
        if (dnd->len == 7 && memcmp(dnd->name, "cmd.exe", 7) == 0) {
            result = 1;
        }

        DetectFilemagicFree(dnd);
        return result;
    }
    return 0;
}

#endif /* UNITTESTS */

/**
 * \brief this function registers unit tests for DetectFilemagic
 */
void DetectFilemagicRegisterTests(void)
{
#ifdef UNITTESTS /* UNITTESTS */
    UtRegisterTest("DetectFilemagicTestParse01", DetectFilemagicTestParse01, 1);
    UtRegisterTest("DetectFilemagicTestParse02", DetectFilemagicTestParse02, 1);
    UtRegisterTest("DetectFilemagicTestParse03", DetectFilemagicTestParse03, 1);
#endif /* UNITTESTS */
}

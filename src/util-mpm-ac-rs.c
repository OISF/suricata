/* Copyright (C) 2007-2023 Open Information Security Foundation
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
 * Wrapper around "aho-corasick" Rust crate.
 */

#include "suricata-common.h"
#include "suricata.h"
#include "rust.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-build.h"

#include "conf.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-memcmp.h"
#include "util-mpm-ac-rs.h"
#include "util-memcpy.h"
#include "util-validate.h"

/**
 * \brief Process the patterns added to the mpm, and create the internal tables.
 *
 * \param mpm_ctx Pointer to the mpm context.
 */
static int SCACRSPreparePatterns(MpmCtx *mpm_ctx)
{
    if (mpm_ctx->pattern_cnt == 0 || mpm_ctx->init_hash == NULL) {
        SCLogDebug("no patterns supplied to this mpm_ctx");
        return 0;
    }

    AhoCorasickStateBuilder *builder = rs_mpm_acrs_new_builder();
    if (builder == NULL)
        return -1;

    /* populate it with the patterns in the hash */
    for (uint32_t i = 0; i < MPM_INIT_HASH_SIZE; i++) {
        MpmPattern *node = mpm_ctx->init_hash[i], *nnode = NULL;
        while (node != NULL) {
            nnode = node->next;

            if (node->cs) {
                rs_mpm_acrs_add_pattern(builder, node->cs, node->len, node->sids, node->sids_size,
                        (node->flags & MPM_PATTERN_FLAG_NOCASE) != 0, node->offset, node->depth);
            } else {
                rs_mpm_acrs_add_pattern(builder, node->ci, node->len, node->sids, node->sids_size,
                        (node->flags & MPM_PATTERN_FLAG_NOCASE) != 0, node->offset, node->depth);
            }

            MpmFreePattern(mpm_ctx, node);

            node = nnode;
        }
    }
    /* we no longer need the hash, so free it's memory */
    SCFree(mpm_ctx->init_hash);
    mpm_ctx->init_hash = NULL;

    mpm_ctx->ctx = rs_mpm_acrs_prepare_builder(builder);
    rs_mpm_acrs_free_builder(builder);
    SCLogDebug("mpm_ctx->ctx %p", mpm_ctx->ctx);
    return 0;
}

/**
 * \brief Initialize the AC context.
 *
 * \param mpm_ctx       Mpm context.
 * \todo it seems we can be called multiple times, probably due to MpmCtx::ctx not
 *       getting initialized yet until "Prepare".
 */
static void SCACRSInitCtx(MpmCtx *mpm_ctx)
{
    /* initialize the hash we use to speed up pattern insertions */
    if (mpm_ctx->init_hash == NULL) {
        mpm_ctx->init_hash = SCCalloc(MPM_INIT_HASH_SIZE, sizeof(MpmPattern *));
        if (mpm_ctx->init_hash == NULL) {
            FatalError("calloc mpm_ctx->init_hash failed");
        }
    }
}

/**
 * \brief Destroy the mpm context.
 *
 * \param mpm_ctx Pointer to the mpm context.
 */
static void SCACRSDestroyCtx(MpmCtx *mpm_ctx)
{
    if (mpm_ctx->init_hash != NULL) {
        for (uint32_t i = 0; i < MPM_INIT_HASH_SIZE; i++) {
            MpmPattern *node = mpm_ctx->init_hash[i];
            while (node != NULL) {
                MpmPattern *next = node->next;
                MpmFreePattern(mpm_ctx, node);
                node = next;
            }
        }
        SCFree(mpm_ctx->init_hash);
        mpm_ctx->init_hash = NULL;
    }
    if (mpm_ctx->ctx) {
        rs_mpm_acrs_state_free(mpm_ctx->ctx);
        mpm_ctx->ctx = NULL;
    }
}

static void SCACRSSearchAddSids(void *pmqv, const uint32_t *sids, uint32_t size)
{
    PrefilterAddSids(pmqv, sids, size);
}

/**
 * \brief The aho corasick search function.
 *
 * \param mpm_ctx        Pointer to the mpm context.
 * \param mpm_thread_ctx Pointer to the mpm thread context.
 * \param pmq            Pointer to the Pattern Matcher Queue to hold
 *                       search matches.
 * \param buf            Buffer to be searched.
 * \param buflen         Buffer length.
 *
 * \retval matches Match count.
 */
static uint32_t SCACRSSearch(const MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx,
        PrefilterRuleStore *pmq, const uint8_t *buf, uint32_t buflen)
{
    uint32_t r = rs_mpm_acrs_search(mpm_ctx->ctx, buf, buflen, SCACRSSearchAddSids, pmq);
    return r;
}

/**
 * \brief Add a case insensitive pattern.  Although we have different calls for
 *        adding case sensitive and insensitive patterns, we make a single call
 *        for either case.  No special treatment for either case.
 *
 * \param mpm_ctx Pointer to the mpm context.
 * \param pat     The pattern to add.
 * \param patnen  The pattern length.
 * \param offset  Ignored.
 * \param depth   Ignored.
 * \param pid     The pattern id.
 * \param sid     Ignored.
 * \param flags   Flags associated with this pattern.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
static int SCACRSAddPatternCI(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen, uint16_t offset,
        uint16_t depth, uint32_t pid, SigIntId sid, uint8_t flags)
{
    flags |= MPM_PATTERN_FLAG_NOCASE;
    return MpmAddPattern(mpm_ctx, pat, patlen, offset, depth, pid, sid, flags);
}

/**
 * \brief Add a case sensitive pattern.  Although we have different calls for
 *        adding case sensitive and insensitive patterns, we make a single call
 *        for either case.  No special treatment for either case.
 *
 * \param mpm_ctx Pointer to the mpm context.
 * \param pat     The pattern to add.
 * \param patnen  The pattern length.
 * \param offset  Ignored.
 * \param depth   Ignored.
 * \param pid     The pattern id.
 * \param sid     Ignored.
 * \param flags   Flags associated with this pattern.
 *
 * \retval  0 On success.
 * \retval -1 On failure.
 */
static int SCACRSAddPatternCS(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen, uint16_t offset,
        uint16_t depth, uint32_t pid, SigIntId sid, uint8_t flags)
{
    return MpmAddPattern(mpm_ctx, pat, patlen, offset, depth, pid, sid, flags);
}

static void SCACRSPrintInfo(MpmCtx *mpm_ctx)
{
    printf("MPM AC Information:\n");
    printf("Memory allocs:   %" PRIu32 "\n", mpm_ctx->memory_cnt);
    printf("Memory alloced:  %" PRIu32 "\n", mpm_ctx->memory_size);
    printf(" Sizeof:\n");
    printf("  MpmCtx         %" PRIuMAX "\n", (uintmax_t)sizeof(MpmCtx));
    printf("  MpmPattern     %" PRIuMAX "\n", (uintmax_t)sizeof(MpmPattern));
    printf("Unique Patterns: %" PRIu32 "\n", mpm_ctx->pattern_cnt);
    printf("Smallest:        %" PRIu32 "\n", mpm_ctx->minlen);
    printf("Largest:         %" PRIu32 "\n", mpm_ctx->maxlen);
    printf("\n");

    return;
}

/************************** Mpm Registration ***************************/

#ifdef UNITTESTS
static void SCACRSRegisterTests(void);
#endif

/**
 * \brief Register the aho-corasick mpm.
 */
void MpmACRSRegister(void)
{
    mpm_table[MPM_AC_RS].name = "ac-rs";
    mpm_table[MPM_AC_RS].InitCtx = SCACRSInitCtx;
    mpm_table[MPM_AC_RS].DestroyCtx = SCACRSDestroyCtx;
    mpm_table[MPM_AC_RS].AddPattern = SCACRSAddPatternCS;
    mpm_table[MPM_AC_RS].AddPatternNocase = SCACRSAddPatternCI;
    mpm_table[MPM_AC_RS].Prepare = SCACRSPreparePatterns;
    mpm_table[MPM_AC_RS].Search = SCACRSSearch;
    mpm_table[MPM_AC_RS].PrintCtx = SCACRSPrintInfo;
#ifdef UNITTESTS
    mpm_table[MPM_AC_RS].RegisterUnittests = SCACRSRegisterTests;
#endif
}

/*************************************Unittests********************************/

#ifdef UNITTESTS
#include "detect-engine-alert.h"

static int SCACRSTest01(void)
{
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_RS);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACRSPreparePatterns(&mpm_ctx);

    const char *buf = "abcdefghjiklmnopqrstuvwxyz";

    uint32_t cnt = SCACRSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf, strlen(buf));
    FAIL_IF_NOT(cnt == 1);

    SCACRSDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    PASS;
}

static int SCACRSTest02(void)
{
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_RS);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abce", 4, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACRSPreparePatterns(&mpm_ctx);

    const char *buf = "abcdefghjiklmnopqrstuvwxyz";
    uint32_t cnt = SCACRSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf, strlen(buf));
    FAIL_IF_NOT(cnt == 0);
    SCACRSDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    PASS;
}

static int SCACRSTest03(void)
{
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_RS);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"bcde", 4, 0, 0, 1, 0, 0);
    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"fghj", 4, 0, 0, 2, 0, 0);
    PmqSetup(&pmq);

    SCACRSPreparePatterns(&mpm_ctx);

    const char *buf = "abcdefghjiklmnopqrstuvwxyz";
    uint32_t cnt = SCACRSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf, strlen(buf));
    FAIL_IF_NOT(cnt == 3);

    SCACRSDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    PASS;
}

static int SCACRSTest04(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_RS);

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"bcdegh", 6, 0, 0, 1, 0, 0);
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"fghjxyz", 7, 0, 0, 2, 0, 0);
    PmqSetup(&pmq);

    SCACRSPreparePatterns(&mpm_ctx);

    const char *buf = "abcdefghjiklmnopqrstuvwxyz";
    uint32_t cnt = SCACRSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ", cnt);

    SCACRSDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACRSTest05(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_RS);

    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"ABCD", 4, 0, 0, 0, 0, 0);
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"bCdEfG", 6, 0, 0, 1, 0, 0);
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"fghJikl", 7, 0, 0, 2, 0, 0);
    PmqSetup(&pmq);

    SCACRSPreparePatterns(&mpm_ctx);

    const char *buf = "abcdefghjiklmnopqrstuvwxyz";
    uint32_t cnt = SCACRSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf, strlen(buf));

    if (cnt == 3)
        result = 1;
    else
        printf("3 != %" PRIu32 " ", cnt);

    SCACRSDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACRSTest06(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_RS);

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACRSPreparePatterns(&mpm_ctx);

    const char *buf = "abcd";
    uint32_t cnt = SCACRSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ", cnt);

    SCACRSDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACRSTest07(void)
{
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_RS);

    /* should match 30 times */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"A", 1, 0, 0, 0, 0, 0);
    /* should match 29 times */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AA", 2, 0, 0, 1, 0, 0);
    /* should match 28 times */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AAA", 3, 0, 0, 2, 0, 0);
    /* 26 */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AAAAA", 5, 0, 0, 3, 0, 0);
    /* 21 */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AAAAAAAAAA", 10, 0, 0, 4, 0, 0);
    /* 1 */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 30, 0, 0, 5, 0, 0);
    PmqSetup(&pmq);
    /* total matches: 135 -> however we count only 1 per pattern */

    SCACRSPreparePatterns(&mpm_ctx);

    const char *buf = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    uint32_t cnt = SCACRSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf, strlen(buf));
    FAIL_IF_NOT(cnt == 6);

    SCACRSDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    PASS;
}

static int SCACRSTest08(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_RS);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACRSPreparePatterns(&mpm_ctx);

    uint32_t cnt = SCACRSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)"a", 1);

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ", cnt);

    SCACRSDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACRSTest09(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_RS);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"ab", 2, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACRSPreparePatterns(&mpm_ctx);

    uint32_t cnt = SCACRSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)"ab", 2);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ", cnt);

    SCACRSDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACRSTest10(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_RS);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcdefgh", 8, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACRSPreparePatterns(&mpm_ctx);

    const char *buf = "01234567890123456789012345678901234567890123456789"
                      "01234567890123456789012345678901234567890123456789"
                      "abcdefgh"
                      "01234567890123456789012345678901234567890123456789"
                      "01234567890123456789012345678901234567890123456789";
    uint32_t cnt = SCACRSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ", cnt);

    SCACRSDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACRSTest11(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_RS);

    if (MpmAddPatternCS(&mpm_ctx, (uint8_t *)"he", 2, 0, 0, 1, 0, 0) == -1)
        goto end;
    if (MpmAddPatternCS(&mpm_ctx, (uint8_t *)"she", 3, 0, 0, 2, 0, 0) == -1)
        goto end;
    if (MpmAddPatternCS(&mpm_ctx, (uint8_t *)"his", 3, 0, 0, 3, 0, 0) == -1)
        goto end;
    if (MpmAddPatternCS(&mpm_ctx, (uint8_t *)"hers", 4, 0, 0, 4, 0, 0) == -1)
        goto end;
    PmqSetup(&pmq);

    if (SCACRSPreparePatterns(&mpm_ctx) == -1)
        goto end;

    result = 1;

    const char *buf = "he";
    result &= (SCACRSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf, strlen(buf)) == 1);
    buf = "she";
    result &= (SCACRSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf, strlen(buf)) == 2);
    buf = "his";
    result &= (SCACRSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf, strlen(buf)) == 1);
    buf = "hers";
    result &= (SCACRSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf, strlen(buf)) == 2);

end:
    SCACRSDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACRSTest12(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_RS);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"wxyz", 4, 0, 0, 0, 0, 0);
    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"vwxyz", 5, 0, 0, 1, 0, 0);
    PmqSetup(&pmq);

    SCACRSPreparePatterns(&mpm_ctx);

    const char *buf = "abcdefghijklmnopqrstuvwxyz";
    uint32_t cnt = SCACRSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf, strlen(buf));

    if (cnt == 2)
        result = 1;
    else
        printf("2 != %" PRIu32 " ", cnt);

    SCACRSDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACRSTest13(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_RS);

    /* 1 match */
    const char pat[] = "abcdefghijklmnopqrstuvwxyzABCD";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, sizeof(pat) - 1, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACRSPreparePatterns(&mpm_ctx);

    const char *buf = "abcdefghijklmnopqrstuvwxyzABCD";
    uint32_t cnt = SCACRSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ", cnt);

    SCACRSDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACRSTest14(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_RS);

    /* 1 match */
    const char pat[] = "abcdefghijklmnopqrstuvwxyzABCDE";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, sizeof(pat) - 1, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACRSPreparePatterns(&mpm_ctx);

    const char *buf = "abcdefghijklmnopqrstuvwxyzABCDE";
    uint32_t cnt = SCACRSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ", cnt);

    SCACRSDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACRSTest15(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_RS);

    /* 1 match */
    const char pat[] = "abcdefghijklmnopqrstuvwxyzABCDEF";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, sizeof(pat) - 1, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACRSPreparePatterns(&mpm_ctx);

    const char *buf = "abcdefghijklmnopqrstuvwxyzABCDEF";
    uint32_t cnt = SCACRSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ", cnt);

    SCACRSDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACRSTest16(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_RS);

    /* 1 match */
    const char pat[] = "abcdefghijklmnopqrstuvwxyzABC";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, sizeof(pat) - 1, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACRSPreparePatterns(&mpm_ctx);

    const char *buf = "abcdefghijklmnopqrstuvwxyzABC";
    uint32_t cnt = SCACRSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ", cnt);

    SCACRSDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACRSTest17(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_RS);

    /* 1 match */
    const char pat[] = "abcdefghijklmnopqrstuvwxyzAB";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, sizeof(pat) - 1, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACRSPreparePatterns(&mpm_ctx);

    const char *buf = "abcdefghijklmnopqrstuvwxyzAB";
    uint32_t cnt = SCACRSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ", cnt);

    SCACRSDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACRSTest18(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_RS);

    /* 1 match */
    const char pat[] = "abcde"
                       "fghij"
                       "klmno"
                       "pqrst"
                       "uvwxy"
                       "z";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, sizeof(pat) - 1, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACRSPreparePatterns(&mpm_ctx);

    const char *buf = "abcde"
                      "fghij"
                      "klmno"
                      "pqrst"
                      "uvwxy"
                      "z";
    uint32_t cnt = SCACRSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ", cnt);

    SCACRSDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACRSTest19(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_RS);

    /* 1 */
    const char pat[] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, sizeof(pat) - 1, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACRSPreparePatterns(&mpm_ctx);

    const char *buf = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    uint32_t cnt = SCACRSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ", cnt);

    SCACRSDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACRSTest20(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_RS);

    /* 1 */
    const char pat[] = "AAAAA"
                       "AAAAA"
                       "AAAAA"
                       "AAAAA"
                       "AAAAA"
                       "AAAAA"
                       "AA";
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)pat, sizeof(pat) - 1, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACRSPreparePatterns(&mpm_ctx);

    const char *buf = "AAAAA"
                      "AAAAA"
                      "AAAAA"
                      "AAAAA"
                      "AAAAA"
                      "AAAAA"
                      "AA";
    uint32_t cnt = SCACRSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ", cnt);

    SCACRSDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACRSTest21(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_RS);

    /* 1 */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AA", 2, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACRSPreparePatterns(&mpm_ctx);

    uint32_t cnt = SCACRSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)"AA", 2);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ", cnt);

    SCACRSDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACRSTest22(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_RS);

    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0);
    /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcde", 5, 0, 0, 1, 0, 0);
    PmqSetup(&pmq);

    SCACRSPreparePatterns(&mpm_ctx);

    const char *buf = "abcdefghijklmnopqrstuvwxyz";
    uint32_t cnt = SCACRSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf, strlen(buf));

    if (cnt == 2)
        result = 1;
    else
        printf("2 != %" PRIu32 " ", cnt);

    SCACRSDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACRSTest23(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_RS);

    /* 1 */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AA", 2, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACRSPreparePatterns(&mpm_ctx);

    uint32_t cnt = SCACRSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)"aa", 2);

    if (cnt == 0)
        result = 1;
    else
        printf("1 != %" PRIu32 " ", cnt);

    SCACRSDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACRSTest24(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_RS);

    /* 1 */
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"AA", 2, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACRSPreparePatterns(&mpm_ctx);

    uint32_t cnt = SCACRSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)"aa", 2);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ", cnt);

    SCACRSDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACRSTest25(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_RS);

    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"ABCD", 4, 0, 0, 0, 0, 0);
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"bCdEfG", 6, 0, 0, 1, 0, 0);
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"fghiJkl", 7, 0, 0, 2, 0, 0);
    PmqSetup(&pmq);

    SCACRSPreparePatterns(&mpm_ctx);

    const char *buf = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    uint32_t cnt = SCACRSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf, strlen(buf));

    if (cnt == 3)
        result = 1;
    else
        printf("3 != %" PRIu32 " ", cnt);

    SCACRSDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACRSTest26(void)
{
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_RS);

    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"Works", 5, 0, 0, 0, 0, 0);
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"Works", 5, 0, 0, 1, 0, 0);
    PmqSetup(&pmq);

    SCACRSPreparePatterns(&mpm_ctx);

    const char *buf = "works";
    uint32_t cnt = SCACRSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf, strlen(buf));
    FAIL_IF_NOT(cnt == 1);

    SCACRSDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    PASS;
}

static int SCACRSTest27(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_RS);

    /* 0 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"ONE", 3, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACRSPreparePatterns(&mpm_ctx);

    const char *buf = "tone";
    uint32_t cnt = SCACRSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf, strlen(buf));

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ", cnt);

    SCACRSDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACRSTest28(void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    PrefilterRuleStore pmq;

    memset(&mpm_ctx, 0, sizeof(MpmCtx));
    memset(&mpm_thread_ctx, 0, sizeof(MpmThreadCtx));
    MpmInitCtx(&mpm_ctx, MPM_AC_RS);

    /* 0 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"one", 3, 0, 0, 0, 0, 0);
    PmqSetup(&pmq);

    SCACRSPreparePatterns(&mpm_ctx);

    const char *buf = "tONE";
    uint32_t cnt = SCACRSSearch(&mpm_ctx, &mpm_thread_ctx, &pmq, (uint8_t *)buf, strlen(buf));

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ", cnt);

    SCACRSDestroyCtx(&mpm_ctx);
    PmqFree(&pmq);
    return result;
}

static int SCACRSTest29(void)
{
    uint8_t buf[] = "onetwothreefourfivesixseveneightnine";
    uint16_t buflen = sizeof(buf) - 1;
    Packet *p = NULL;
    ThreadVars th_v;
    DetectEngineThreadCtx *det_ctx = NULL;
    int result = 0;

    memset(&th_v, 0, sizeof(th_v));
    p = UTHBuildPacket(buf, buflen, IPPROTO_TCP);

    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    if (de_ctx == NULL)
        goto end;

    de_ctx->flags |= DE_QUIET;

    de_ctx->sig_list =
            SigInit(de_ctx, "alert tcp any any -> any any "
                            "(content:\"onetwothreefourfivesixseveneightnine\"; sid:1;)");
    if (de_ctx->sig_list == NULL)
        goto end;
    de_ctx->sig_list->next = SigInit(de_ctx,
            "alert tcp any any -> any any "
            "(content:\"onetwothreefourfivesixseveneightnine\"; fast_pattern:3,3; sid:2;)");
    if (de_ctx->sig_list->next == NULL)
        goto end;

    SigGroupBuild(de_ctx);
    DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

    SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
    if (PacketAlertCheck(p, 1) != 1) {
        printf("if (PacketAlertCheck(p, 1) != 1) failure\n");
        goto end;
    }
    if (PacketAlertCheck(p, 2) != 1) {
        printf("if (PacketAlertCheck(p, 1) != 2) failure\n");
        goto end;
    }

    result = 1;
end:
    if (de_ctx != NULL) {
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);

        DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);
        DetectEngineCtxFree(de_ctx);
    }

    UTHFreePackets(&p, 1);
    return result;
}

static void SCACRSRegisterTests(void)
{
    UtRegisterTest("SCACRSTest01", SCACRSTest01);
    UtRegisterTest("SCACRSTest02", SCACRSTest02);
    UtRegisterTest("SCACRSTest03", SCACRSTest03);
    UtRegisterTest("SCACRSTest04", SCACRSTest04);
    UtRegisterTest("SCACRSTest05", SCACRSTest05);
    UtRegisterTest("SCACRSTest06", SCACRSTest06);
    UtRegisterTest("SCACRSTest07", SCACRSTest07);
    UtRegisterTest("SCACRSTest08", SCACRSTest08);
    UtRegisterTest("SCACRSTest09", SCACRSTest09);
    UtRegisterTest("SCACRSTest10", SCACRSTest10);
    UtRegisterTest("SCACRSTest11", SCACRSTest11);
    UtRegisterTest("SCACRSTest12", SCACRSTest12);
    UtRegisterTest("SCACRSTest13", SCACRSTest13);
    UtRegisterTest("SCACRSTest14", SCACRSTest14);
    UtRegisterTest("SCACRSTest15", SCACRSTest15);
    UtRegisterTest("SCACRSTest16", SCACRSTest16);
    UtRegisterTest("SCACRSTest17", SCACRSTest17);
    UtRegisterTest("SCACRSTest18", SCACRSTest18);
    UtRegisterTest("SCACRSTest19", SCACRSTest19);
    UtRegisterTest("SCACRSTest20", SCACRSTest20);
    UtRegisterTest("SCACRSTest21", SCACRSTest21);
    UtRegisterTest("SCACRSTest22", SCACRSTest22);
    UtRegisterTest("SCACRSTest23", SCACRSTest23);
    UtRegisterTest("SCACRSTest24", SCACRSTest24);
    UtRegisterTest("SCACRSTest25", SCACRSTest25);
    UtRegisterTest("SCACRSTest26", SCACRSTest26);
    UtRegisterTest("SCACRSTest27", SCACRSTest27);
    UtRegisterTest("SCACRSTest28", SCACRSTest28);
    UtRegisterTest("SCACRSTest29", SCACRSTest29);
}
#endif

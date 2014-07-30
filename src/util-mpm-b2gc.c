/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * Implementation of the SBNDMq pattern matching algorithm that tries
 * to be very limiting memory use and CPU cache efficient.
 *
 * Things to try:
 * - 1 byte pattern checks use lowercase *buf for hash, limiting the hash
 * - lookup array with pminlen and pminlenb like in B2gm
 */

//#define PRINTMATCH

#include "suricata-common.h"
#include "suricata.h"
#include "detect.h"

#include "util-mpm-b2gc.h"
#include "util-print.h"
#include "util-bloomfilter.h"
#include "util-debug.h"
#include "util-unittest.h"
#include "util-hashlist.h"
#include "util-optimize.h"
#include "util-memcmp.h"

#include "conf.h"

#ifdef B2GC_COUNTERS
#define COUNT(counter) \
        (counter)
#else
#define COUNT(counter)
#endif /* B2GC_COUNTERS */

/* Hash table used at ctx initialization to keep and ordered list of
 * patterns. The ordered list is used to build the ordered lookup
 * array. */
static uint32_t b2gc_hash_size = 0;
static int8_t b2gc_hash_shift = 0;
static uint32_t b2gc_bloom_size = 0;
static void *b2g_func;

#define B2GC_HASH16(a,b) (((a) << b2gc_hash_shift) | (b))

#define B2GC_PMINLEN_MAX    8

/* align pattern storage to these bytes. 1 disables. */
#define B2GC_ALIGN_PATTERNS 2

void B2gcInitCtx (MpmCtx *);
void B2gcThreadInitCtx(MpmCtx *, MpmThreadCtx *, uint32_t);
void B2gcDestroyCtx(MpmCtx *);
void B2gcThreadDestroyCtx(MpmCtx *, MpmThreadCtx *);
int B2gcAddPatternCI(MpmCtx *, uint8_t *, uint16_t, uint16_t, uint16_t, uint32_t, uint32_t, uint8_t);
int B2gcAddPatternCS(MpmCtx *, uint8_t *, uint16_t, uint16_t, uint16_t, uint32_t, uint32_t, uint8_t);
int B2gcPreparePatterns(MpmCtx *mpm_ctx);
uint32_t B2gcSearchWrap(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx, PatternMatcherQueue *, uint8_t *buf, uint16_t buflen);
uint32_t B2gcSearch1(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx, PatternMatcherQueue *, uint8_t *buf, uint16_t buflen);
#ifdef B2GC_SEARCH2
uint32_t B2gcSearch2(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx, PatternMatcherQueue *, uint8_t *buf, uint16_t buflen);
#endif
uint32_t B2gcSearch(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx, PatternMatcherQueue *, uint8_t *buf, uint16_t buflen);
uint32_t B2gcSearchBNDMq(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx, PatternMatcherQueue *pmq, uint8_t *buf, uint16_t buflen);
void B2gcPrintInfo(MpmCtx *mpm_ctx);
void B2gcPrintSearchStats(MpmThreadCtx *mpm_thread_ctx);
void B2gcRegisterTests(void);

void MpmB2gcRegister (void)
{
    mpm_table[MPM_B2GC].name = "b2gc";
    mpm_table[MPM_B2GC].max_pattern_length = B2GC_WORD_SIZE;

    mpm_table[MPM_B2GC].InitCtx = B2gcInitCtx;
    mpm_table[MPM_B2GC].InitThreadCtx = B2gcThreadInitCtx;
    mpm_table[MPM_B2GC].DestroyCtx = B2gcDestroyCtx;
    mpm_table[MPM_B2GC].DestroyThreadCtx = B2gcThreadDestroyCtx;
    mpm_table[MPM_B2GC].AddPattern = B2gcAddPatternCS;
    mpm_table[MPM_B2GC].AddPatternNocase = B2gcAddPatternCI;
    mpm_table[MPM_B2GC].Prepare = B2gcPreparePatterns;
    mpm_table[MPM_B2GC].Search = B2gcSearchWrap;
    mpm_table[MPM_B2GC].Cleanup = NULL;
    mpm_table[MPM_B2GC].PrintCtx = B2gcPrintInfo;
    mpm_table[MPM_B2GC].PrintThreadCtx = B2gcPrintSearchStats;
    mpm_table[MPM_B2GC].RegisterUnittests = B2gcRegisterTests;
}

#ifdef PRINTMATCH
static void prt (uint8_t *buf, uint16_t buflen)
{
    uint16_t i;

    for (i = 0; i < buflen; i++) {
        if (isprint(buf[i])) printf("%c", buf[i]);
        else                 printf("\\x%02X", buf[i]);
    }
    //printf("\n");
}
#endif

void B2gcPrintInfo(MpmCtx *mpm_ctx)
{
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx->ctx;

    printf("MPM B2gc Information:\n");
    printf("Memory allocs:   %" PRIu32 "\n", mpm_ctx->memory_cnt);
    printf("Memory alloced:  %" PRIu32 "\n", mpm_ctx->memory_size);
    printf(" Sizeofs:\n");
    printf("  MpmCtx         %" PRIuMAX "\n", (uintmax_t)sizeof(MpmCtx));
    printf("  B2gcCtx:       %" PRIuMAX "\n", (uintmax_t)sizeof(B2gcCtx));
    printf("  B2gcPattern    %" PRIuMAX "\n", (uintmax_t)sizeof(B2gcPattern));
    printf("Unique Patterns: %" PRIu32 "\n", mpm_ctx->pattern_cnt);
    printf("Smallest:        %" PRIu32 "\n", mpm_ctx->minlen);
    printf("Largest:         %" PRIu32 "\n", mpm_ctx->maxlen);
    printf("Hash size:       %" PRIu32 "\n", ctx->hash_size);
    printf("\n");
}

static inline int
memcmp_lowercase(const uint8_t *s1, const uint8_t *s2, const uint16_t n)
{
    size_t i;

    /* check backwards because we already tested the first
     * 2 to 4 chars. This way we are more likely to detect
     * a miss and thus speed up a little... */
    for (i = n - 1; i; i--) {
        //if (u8_tolower(*(s2+i)) != u8_tolower(s1[i]))
        if (s1[i] != u8_tolower(*(s2+i)))
            return 1;
    }

    return 0;
}

static inline int
memcmp_lowercase2(uint8_t *s1, uint8_t *s2, uint16_t n)
{
    size_t i;

    /* check backwards because we already tested the first
     * 2 to 4 chars. This way we are more likely to detect
     * a miss and thus speed up a little... */
    for (i = n - 1; i; i--) {
        //if (u8_tolower(*(s2+i)) != u8_tolower(s1[i]))
        if (u8_tolower(s1[i]) != u8_tolower(*(s2+i)))
            return 1;
    }

    return 0;
}

static inline void memcpy_tolower(uint8_t *d, uint8_t *s, uint16_t len)
{
    uint16_t i;
    for (i = 0; i < len; i++) {
        d[i] = u8_tolower(s[i]);
    }
}

static inline B2gcPattern *B2gcAllocPattern(MpmCtx *mpm_ctx)
{
    B2gcPattern *p = SCMalloc(sizeof(B2gcPattern));
    if (unlikely(p == NULL))
        return NULL;
    memset(p,0,sizeof(B2gcPattern));

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += sizeof(B2gcPattern);
    return p;
}

/** \internal
 *  \brief Free a init hash pattern
 */
static void B2gcFreePattern(MpmCtx *mpm_ctx, B2gcPattern *p)
{
    if (p != NULL) {
        if (p->pat != NULL) {
            SCFree(p->pat);
            mpm_ctx->memory_cnt--;
            mpm_ctx->memory_size -= p->len;
        }

        SCFree(p);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= sizeof(B2gcPattern);
    }
}

/** \internal
 *  \brief add a pattern to the mpm/b2g context
 *
 *  \param pat ptr to the pattern
 *  \param patlen length of the pattern
 *  \param pid pattern id
 *  \param sid signature id (internal id)
 *  \param flags pattern MPM_PATTERN_* flags
 */
static int B2gcAddPattern(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen, uint16_t offset, uint16_t depth, uint32_t pid, uint32_t sid, uint8_t flags)
{
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx->ctx;

    SCLogDebug("ctx %p len %"PRIu16" pid %" PRIu32, ctx, patlen, pid);

    if (patlen == 0)
        return 0;

    /* detect duplicate pattern adds */
    B2gcPattern lookup_p = { patlen, flags, 0, pid, pat };

    /* get a memory piece */
    B2gcPattern *p = HashListTableLookup(ctx->b2gc_init_hash, (void *)&lookup_p, sizeof(B2gcPattern));
    if (p == NULL) {
        SCLogDebug("allocing new pattern");

        p = B2gcAllocPattern(mpm_ctx);
        if (p == NULL)
            goto error;

        p->len = patlen;
        p->flags = flags;
        p->id = pid;

        p->pat = SCMalloc(patlen);
        if (p->pat == NULL)
            goto error;

        mpm_ctx->memory_cnt++;
        mpm_ctx->memory_size += patlen;

        memcpy(p->pat, pat, patlen);

        /* put in the pattern hash */
        HashListTableAdd(ctx->b2gc_init_hash, (void *)p, sizeof(B2gcPattern));

        if (mpm_ctx->pattern_cnt == 65535) {
            printf("Max search words reached\n");
            exit(1);
        }
        mpm_ctx->pattern_cnt++;

        if (mpm_ctx->maxlen < patlen)
            mpm_ctx->maxlen = patlen;
        if (mpm_ctx->minlen == 0)
            mpm_ctx->minlen = patlen;
        else if (mpm_ctx->minlen > patlen)
            mpm_ctx->minlen = patlen;
}
    return 0;

error:
    B2gcFreePattern(mpm_ctx, p);
    return -1;
}

int B2gcAddPatternCI(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
    uint16_t offset, uint16_t depth, uint32_t pid, uint32_t sid, uint8_t flags)
{
    flags |= MPM_PATTERN_FLAG_NOCASE;
    return B2gcAddPattern(mpm_ctx, pat, patlen, offset, depth, pid, sid, flags);
}

int B2gcAddPatternCS(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
    uint16_t offset, uint16_t depth, uint32_t pid, uint32_t sid, uint8_t flags)
{
    return B2gcAddPattern(mpm_ctx, pat, patlen, offset, depth, pid, sid, flags);
}

static inline uint32_t B2gcBloomHash(void *data, uint16_t datalen, uint8_t iter, uint32_t hash_size)
{
     uint8_t *d = (uint8_t *)data;
     uint16_t i;
     uint32_t hash = (uint32_t)u8_tolower(*d);

     for (i = 1; i < datalen; i++) {
         d++;
         hash += (u8_tolower(*d)) ^ i;
     }
     hash <<= (iter+1);

     hash %= hash_size;
     return hash;
}

static uint32_t B2gcHashPatternInitHash(HashListTable *ht, void *pattern, uint16_t len)
{
    BUG_ON(len != sizeof(B2gcPattern));
    BUG_ON(pattern == NULL);

    B2gcPattern *p = (B2gcPattern *)pattern;
    uint32_t hash = 0;

    uint32_t u;
    for (u = 0; u < p->len; u++) {
        hash += (u8_tolower(p->pat[u]));
    }

    return hash % ht->array_size;
}

#define B2GC_SORTHASH_MODE_LL   0
#define B2GC_SORTHASH_MODE_LU   1
#define B2GC_SORTHASH_MODE_UL   2
#define B2GC_SORTHASH_MODE_UU   3
#define B2GC_SORTHASH_MODE_CS   4

/* copy of ctx->m for use in B2gcHashPatternSortHash */
static B2GC_TYPE m;
static int b2gc_sorthash_mode = B2GC_SORTHASH_MODE_LL;

static uint32_t B2gcHashPatternSortHash(HashListTable *ht, void *pattern, uint16_t len)
{
    BUG_ON(len != sizeof(B2gcPattern));
    BUG_ON(pattern == NULL);

    B2gcPattern *p = (B2gcPattern *)pattern;
    uint32_t hash = 0;
    if (b2gc_sorthash_mode == B2GC_SORTHASH_MODE_LL) {
        hash = B2GC_HASH16(u8_tolower(p->pat[m - 2]), u8_tolower(p->pat[m - 1]));
    } else if(b2gc_sorthash_mode == B2GC_SORTHASH_MODE_LU) {
        hash = B2GC_HASH16(u8_tolower(p->pat[m - 2]), toupper(p->pat[m - 1]));
    } else if(b2gc_sorthash_mode == B2GC_SORTHASH_MODE_UL) {
        hash = B2GC_HASH16(toupper(p->pat[m - 2]), u8_tolower(p->pat[m - 1]));
    } else if (b2gc_sorthash_mode == B2GC_SORTHASH_MODE_UU) {
        hash = B2GC_HASH16(toupper(p->pat[m - 2]), toupper(p->pat[m - 1]));
    } else {
        hash = B2GC_HASH16(p->pat[m - 2], p->pat[m - 1]);
    }
    SCReturnUInt(hash);
}

static uint32_t B2gcHashPatternSortHash1(HashListTable *ht, void *pattern, uint16_t len)
{
    BUG_ON(len != sizeof(B2gcPattern));
    BUG_ON(pattern == NULL);

    B2gcPattern *p = (B2gcPattern *)pattern;
    return (uint32_t)u8_tolower(p->pat[0]);
}

static char B2gcHashPatternCompare(void *pattern1, uint16_t len1,
        void *pattern2, uint16_t len2)
{
    BUG_ON(len1 != sizeof(B2gcPattern));
    BUG_ON(len2 != sizeof(B2gcPattern));

    B2gcPattern *p1 = (B2gcPattern *)pattern1;
    B2gcPattern *p2 = (B2gcPattern *)pattern2;

    if (p1->id != p2->id) {
        return 0;
    }

    return 1;
}

static void B2gcHashPatternFree(void *pattern)
{
    B2gcPattern *p = (B2gcPattern *)pattern;

    SCFree(p->pat);

    SCFree(pattern);
}

static void B2gcAddToMatchArray(MpmCtx *mpm_ctx, B2gcPattern *p, int j)
{
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx->ctx;

    if (p->flags & MPM_PATTERN_FLAG_NOCASE) {
        /* u, u */
        uint16_t uuidx = B2GC_HASH16(toupper(p->pat[j]), toupper(p->pat[j + 1]));
        ctx->B2GC[uuidx] = ctx->B2GC[uuidx] | (1 << (ctx->m - j));

        /* l, l */
        uint16_t llidx = B2GC_HASH16(u8_tolower(p->pat[j]), u8_tolower(p->pat[j + 1]));
        if (llidx != uuidx) {
            ctx->B2GC[llidx] = ctx->B2GC[llidx] | (1 << (ctx->m - j));
        }
        /* u, l */
        uint16_t ulidx = B2GC_HASH16(toupper(p->pat[j]), u8_tolower(p->pat[j + 1]));
        if (ulidx != llidx && ulidx != uuidx) {
            ctx->B2GC[ulidx] = ctx->B2GC[ulidx] | (1 << (ctx->m - j));
        }
        /* l, u */
        uint16_t luidx = B2GC_HASH16(u8_tolower(p->pat[j]), toupper(p->pat[j + 1]));
        if (luidx != ulidx && luidx != llidx && luidx != uuidx) {
            ctx->B2GC[luidx] = ctx->B2GC[luidx] | (1 << (ctx->m - j));
        }

        SCLogDebug("uuidx %u, ulidx %u, luidx %u, llidx %u", uuidx, ulidx, luidx, llidx);
    }
}

int B2gcBuildMatchArray(MpmCtx *mpm_ctx, HashListTable *b2gc_sort_hash)
{
    SCEnter();
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx->ctx;

    ctx->B2GC = SCMalloc(sizeof(B2GC_TYPE) * ctx->hash_size);
    if (ctx->B2GC == NULL)
        return -1;

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += (sizeof(B2GC_TYPE) * ctx->hash_size);

    memset(ctx->B2GC, 0x00, (b2gc_hash_size * sizeof(B2GC_TYPE)));

    uint32_t j;

    /* fill the match array */
    for (j = 0; j <= (ctx->m - B2GC_Q); j++) {
        HashListTableBucket *next = NULL;
        HashListTableBucket *buck = HashListTableGetListHead(b2gc_sort_hash);

        while (buck != NULL) {
            /* get the next before we free "buck" */
            next = HashListTableGetListNext(buck);

            B2gcPattern *p = (B2gcPattern *) HashListTableGetListData(buck);
            BUG_ON(p == NULL);

            if (p->len < ctx->m)
                goto next;

            uint16_t h;
            if (p->flags & MPM_PATTERN_FLAG_NOCASE) {
                B2gcAddToMatchArray(mpm_ctx, p, j);
            } else {
                h = B2GC_HASH16(p->pat[j],p->pat[j+1]);
                ctx->B2GC[h] = ctx->B2GC[h] | (1 << (ctx->m - j));
                SCLogDebug("h %"PRIu16", ctx->B2GC[h] %"PRIu32" (cs)", h, ctx->B2GC[h]);
            }
        next:
            buck = next;
        }
    }

    SCReturnInt(0);
}

static void B2gcAddCopyToHash(MpmCtx *mpm_ctx, HashListTable *ht, B2gcPattern *p)
{
    B2gcPattern *pcopy = B2gcAllocPattern(mpm_ctx);
    BUG_ON(pcopy == NULL);
    pcopy->id = p->id;
    pcopy->flags = p->flags;
    pcopy->len = p->len;

    pcopy->pat = SCMalloc(pcopy->len);
    BUG_ON(pcopy->pat == NULL);

    memcpy(pcopy->pat, p->pat, pcopy->len);

    HashListTableAdd(ht, (void *)pcopy, sizeof(B2gcPattern));
}

static int B2gcAddToHash(MpmCtx *mpm_ctx, HashListTable *b2gc_sort_hash, B2gcPattern *p)
{
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx->ctx;
    int added = 0;
    //printf("%c.%c\n", p->pat[ctx->m - 2], p->pat[ctx->m - 1]);

    if (p->flags & MPM_PATTERN_FLAG_NOCASE) {
        /* u, u */
        uint16_t uuidx = B2GC_HASH16(toupper(p->pat[ctx->m - 2]), toupper(p->pat[ctx->m - 1]));
        b2gc_sorthash_mode = B2GC_SORTHASH_MODE_UU;
        HashListTableAdd(b2gc_sort_hash, (void *)p, sizeof(B2gcPattern));
        added++;

        /* l, l */
        uint16_t llidx = B2GC_HASH16(u8_tolower(p->pat[ctx->m - 2]), u8_tolower(p->pat[ctx->m - 1]));
        if (llidx != uuidx) {
            b2gc_sorthash_mode = B2GC_SORTHASH_MODE_LL;
            B2gcAddCopyToHash(mpm_ctx, b2gc_sort_hash, p);
            added++;
        }
        /* u, l */
        uint16_t ulidx = B2GC_HASH16(toupper(p->pat[ctx->m - 2]), u8_tolower(p->pat[ctx->m - 1]));
        if (ulidx != llidx && ulidx != uuidx) {
            b2gc_sorthash_mode = B2GC_SORTHASH_MODE_UL;
            B2gcAddCopyToHash(mpm_ctx, b2gc_sort_hash, p);
            added++;
        }
        /* l, u */
        uint16_t luidx = B2GC_HASH16(u8_tolower(p->pat[ctx->m - 2]), toupper(p->pat[ctx->m - 1]));
        if (luidx != ulidx && luidx != llidx && luidx != uuidx) {
            b2gc_sorthash_mode = B2GC_SORTHASH_MODE_LU;
            B2gcAddCopyToHash(mpm_ctx, b2gc_sort_hash, p);
            added++;
        }

        SCLogDebug("uuidx %u, ulidx %u, luidx %u, llidx %u", uuidx, ulidx, luidx, llidx);
    }

    return added;
}

static void B2gcPrepareHash(MpmCtx *mpm_ctx)
{
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx->ctx;
    HashListTable *b2gc_sort_hash = NULL;
    HashListTable *b2gc_sort_hash1 = NULL;

    /* make sure ctx->m is set */
    BUG_ON(ctx->m == 0);
    m = ctx->m;

    /* convert b2gc_init_hash to b2gc_sort_hash and count size */
    uint32_t size = B2GC_ALIGN_PATTERNS;
    uint16_t size1 = 1;

    /* only used at init */
    b2gc_sort_hash = HashListTableInit(b2gc_hash_size, B2gcHashPatternSortHash, B2gcHashPatternCompare, B2gcHashPatternFree);
    if (b2gc_sort_hash == NULL) {
        exit(EXIT_FAILURE);
    }

    b2gc_sort_hash1 = HashListTableInit(256, B2gcHashPatternSortHash1, B2gcHashPatternCompare, B2gcHashPatternFree);
    if (b2gc_sort_hash1 == NULL) {
        exit(EXIT_FAILURE);
    }

    HashListTableBucket *next = NULL;
    HashListTableBucket *buck = HashListTableGetListHead(ctx->b2gc_init_hash);
    while (buck != NULL) {
        /* get the next before we free "buck" */
        next = HashListTableGetListNext(buck);

        B2gcPattern *p = (B2gcPattern *) HashListTableGetListData(buck);
        BUG_ON(p == NULL);

        //printf("init_hash: "); prt(p->pat,p->len);printf("\n");
        if (p->len > 1) {
            uint32_t psize;
            if (p->flags & MPM_PATTERN_FLAG_NOCASE) {
                //prt(p->pat, p->len);printf(" (m %u)\n", m);
                int added = B2gcAddToHash(mpm_ctx, b2gc_sort_hash, p);
                SCLogDebug("nocase pattern was added under different hash values %d times", added);

                uint32_t one = sizeof(B2gcPatternHdr) + ((p->len + (p->len % B2GC_ALIGN_PATTERNS)));
                //uint32_t one = sizeof(B2gcPatternHdr) + ((p->len + (p->len % B2GC_ALIGN_PATTERNS)) * 2);
                psize = one * added;
            } else {
                b2gc_sorthash_mode = B2GC_SORTHASH_MODE_CS;
                HashListTableAdd(b2gc_sort_hash, (void *)p, sizeof(B2gcPattern));

                psize = (sizeof(B2gcPatternHdr) + p->len + (p->len % B2GC_ALIGN_PATTERNS));
            }

            size += psize;
        } else {
            HashListTableAdd(b2gc_sort_hash1, (void *)p, sizeof(B2gcPattern));
            size1 += (sizeof(B2gcPattern1));
        }

        buck = next;
    }
    HashListTableFree(ctx->b2gc_init_hash);
    ctx->b2gc_init_hash = NULL;

    SCLogDebug("size %u", size);

    /* alloc buf of size */
    ctx->patterns = SCMalloc(size);
    BUG_ON(ctx->patterns == NULL);
    memset(ctx->patterns, 0x00, size);

    ctx->patterns1 = SCMalloc(size1);
    BUG_ON(ctx->patterns1 == NULL);
    memset(ctx->patterns1, 0x00, size1);

    /* loop through sort list and copy to buf */

    /* skip the first byte of the buffer */
    uint32_t offset = B2GC_ALIGN_PATTERNS;

    /* the hashlist is not sorted, it's in the order of insertion.
     * We need it to be sorted by hash, so here we do something
     * unclean: we bypass the hashlist api. */
    uint32_t a = 0;
    for (a = 0; a < b2gc_sort_hash->array_size; a++) {
        if ((buck = b2gc_sort_hash->array[a]) != NULL) {
            while (buck != NULL) {
                if (buck->data != NULL) {
                    uint32_t prev_offset = offset;
                    B2gcPattern *p = (B2gcPattern *) (buck->data);
                    BUG_ON(p == NULL);
                    BUG_ON(p->len == 1);

                    uint16_t hash = a;//= B2GC_HASH16(u8_tolower(p->pat[m - 2]), u8_tolower(p->pat[m - 1]));
                    if (ctx->pminlen[hash] == 0) {
                        ctx->pminlen[hash] = p->len;
                    } else if (p->len < ctx->pminlen[hash]) {
                        ctx->pminlen[hash] = p->len;
                    }

                    if (ctx->ha[hash] == 0)
                        ctx->ha[hash] = offset;

                    /* copy */
                    B2gcPatternHdr *h = (B2gcPatternHdr *)&ctx->patterns[offset];
                    h->id = p->id;
                    h->len = p->len;
                    if (p->flags & MPM_PATTERN_FLAG_NOCASE) {
                        h->flags |= B2GC_FLAG_NOCASE;
                    }

                    offset += sizeof(B2gcPatternHdr);

                    if (p->flags & MPM_PATTERN_FLAG_NOCASE) {
                        memcpy_tolower(&ctx->patterns[offset], p->pat, p->len);
                    } else {
                        memcpy(&ctx->patterns[offset], p->pat, p->len);
                    }
                    offset += (p->len + (p->len % B2GC_ALIGN_PATTERNS));

                    h->np_offset = offset - prev_offset;

                    SCLogDebug("h->offset %u", offset);

                    ctx->pat_x_cnt++;

                }
                buck = buck->bucknext;
            }
        }
    }

    /* build the hash containing idx' to the pattern array */
    for (a = 0; a < b2gc_hash_size; a++) {
        uint32_t offset = ctx->ha[a];
        uint32_t next_offset = 0;

        if (offset > 0) {
            uint32_t b = a + 1;
            while (b < b2gc_hash_size) {
                if (ctx->ha[b] > 0) {
                    next_offset = ctx->ha[b];
                    break;
                }

                b++;
            }
        }

        while (offset > 0) {
            B2gcPatternHdr *h = (B2gcPatternHdr *)&ctx->patterns[offset];
            BUG_ON(h == NULL);
            BUG_ON(h->len <= 1);

            uint8_t *pattern = (uint8_t *)&ctx->patterns[offset + sizeof(B2gcPatternHdr)];
            BUG_ON(pattern == NULL);
            //printf("hash %u (offset %u, h %u) sort_hash: ", a, offset, ctx->ha[a]);prt(pattern,h->len);printf("\n");

            uint16_t hash = a;

            SCLogDebug("hash %u, offset %u", hash, offset);

            if (ctx->bloom[hash] == NULL) {
                ctx->bloom[hash] = BloomFilterInit(b2gc_bloom_size, 2, B2gcBloomHash);
                SCLogDebug("bloom created for hash %u", hash);
                BUG_ON(ctx->bloom[hash] == NULL);
                mpm_ctx->memory_cnt += BloomFilterMemoryCnt(ctx->bloom[hash]);
                mpm_ctx->memory_size += BloomFilterMemorySize(ctx->bloom[hash]);
            }

            if (ctx->pminlen[hash] > B2GC_PMINLEN_MAX)
                ctx->pminlen[hash] = B2GC_PMINLEN_MAX;

            BloomFilterAdd(ctx->bloom[hash], pattern, ctx->pminlen[hash]);

            offset += h->np_offset;

            /* last item in the pattern storage is "final" too */
            if (offset == size) {
                SCLogDebug("final pattern in the array");
                h->flags |= B2GC_FLAG_FINAL;
                break;
            }

            /* next_offset points to next hash */
            if (next_offset > 0 && offset == next_offset) {
                SCLogDebug("last pattern for this hash");
                h->flags |= B2GC_FLAG_FINAL;
                break;
            }
        }
    }

    /* skip the first byte of the buffer */
    uint16_t offset1 = 1;

    for (a = 0; a < b2gc_sort_hash1->array_size; a++) {
        buck = b2gc_sort_hash1->array[a];
        if (buck != NULL) {
            while (buck != NULL) {
                if (buck->data != NULL) {
                    B2gcPattern *p = (B2gcPattern *) (buck->data);
                    BUG_ON(p == NULL);
                    BUG_ON(p->len != 1);

                    B2gcPattern1 *h = (B2gcPattern1 *)&ctx->patterns1[offset1];
                    h->id = p->id;
                    h->pat = p->pat[0];
                    if (p->flags & MPM_PATTERN_FLAG_NOCASE) {
                        h->flags |= B2GC_FLAG_NOCASE;
                    }

                    offset1 += (sizeof(B2gcPattern1));

                    ctx->pat_1_cnt++;
                }
                buck = buck->bucknext;
            }
        }
    }

    /* build the hash containing idx' to the pattern array */
    offset1 = 1;

    B2gcPattern1 *ph1 = NULL;
    uint8_t prevhash1 = 0;
    while (offset1 < size1) {
        B2gcPattern1 *h = (B2gcPattern1 *)&ctx->patterns1[offset1];

        if (ctx->ha1[u8_tolower(h->pat)] == 0)
            ctx->ha1[u8_tolower(h->pat)] = offset1;

        /* check the prev pattern for setting the final flag */
        if (ph1 != NULL) {
            if (h->pat != prevhash1) {
                SCLogDebug("setting final flag on %p", ph1);
                ph1->flags |= B2GC_FLAG_FINAL;
            }
        }

        prevhash1 = u8_tolower(h->pat);
        ph1 = h;

        offset1 += (sizeof(B2gcPattern1));

        /* last item is "final" too */
        if (offset1 == size1) {
            SCLogDebug("final pattern in the array");
            h->flags |= B2GC_FLAG_FINAL;
        }
    }

    B2gcBuildMatchArray(mpm_ctx, b2gc_sort_hash);

    /* free the hashes only used at init */
    HashListTableFree(b2gc_sort_hash);
    b2gc_sort_hash = NULL;

    HashListTableFree(b2gc_sort_hash1);
    b2gc_sort_hash1 = NULL;
}

int B2gcPreparePatterns(MpmCtx *mpm_ctx)
{
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx->ctx;

    /* set 'm' to the smallest pattern size */
    ctx->m = mpm_ctx->minlen;

    /* make sure 'm' stays in bounds
       m can be max WORD_SIZE - 1 */
    if (ctx->m >= B2GC_WORD_SIZE) {
        ctx->m = B2GC_WORD_SIZE - 1;
    }
    if (ctx->m < 2)
        ctx->m = 2;

    ctx->hash_size = b2gc_hash_size;

    /* alloc the hashes */
    ctx->ha = SCMalloc(b2gc_hash_size * sizeof(uint32_t));
    BUG_ON(ctx->ha == NULL);
    memset(ctx->ha, 0x00, b2gc_hash_size * sizeof(uint32_t));

    ctx->ha1 = SCMalloc(256 * sizeof(uint16_t));
    BUG_ON(ctx->ha1 == NULL);
    memset(ctx->ha1, 0x00, 256 * sizeof(uint16_t));

    /* alloc the bloom array */
    ctx->bloom = (BloomFilter **)SCMalloc(sizeof(BloomFilter *) * ctx->hash_size);
    if (ctx->bloom == NULL)
        exit(EXIT_FAILURE);
    memset(ctx->bloom, 0, sizeof(BloomFilter *) * ctx->hash_size);

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += (sizeof(BloomFilter *) * ctx->hash_size);

    /* alloc the pminlen array */
    ctx->pminlen = (uint8_t *)SCMalloc(sizeof(uint8_t) * ctx->hash_size);
    if (ctx->pminlen == NULL)
        exit(EXIT_FAILURE);
    memset(ctx->pminlen, 0, sizeof(uint8_t) * ctx->hash_size);

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += (sizeof(uint8_t) * ctx->hash_size);

    B2gcPrepareHash(mpm_ctx);

    SCLogDebug("ctx->pat_1_cnt %"PRIu16"", ctx->pat_1_cnt);
    if (ctx->pat_1_cnt) {
        ctx->Search = B2gcSearch1;

        ctx->MBSearch = b2g_func;
    }

    return 0;
}

void B2gcPrintSearchStats(MpmThreadCtx *mpm_thread_ctx)
{
#ifdef B2GC_COUNTERS
    B2gcThreadCtx *tctx = (B2gcThreadCtx *)mpm_thread_ctx->ctx;

    printf("B2gc Thread Search stats (tctx %p)\n", tctx);
    printf("Total calls: %" PRIu32 "\n", tctx->stat_calls);
    printf("Avg m/search: %0.2f\n", tctx->stat_calls ? (float)((float)tctx->stat_m_total / (float)tctx->stat_calls) : 0);
    printf("D != 0 (possible match): %" PRIu32 "\n", tctx->stat_d0);
    printf("Avg hash items per bucket %0.2f (%" PRIu32 ")\n", tctx->stat_d0 ? (float)((float)tctx->stat_d0_hashloop / (float)tctx->stat_d0) : 0, tctx->stat_d0_hashloop);
    printf("Loop match: %" PRIu32 "\n", tctx->stat_loop_match);
    printf("Loop no match: %" PRIu32 "\n", tctx->stat_loop_no_match);
    printf("Num shifts: %" PRIu32 "\n", tctx->stat_num_shift);
    printf("Total shifts: %" PRIu32 "\n", tctx->stat_total_shift);
    printf("Avg shifts: %0.2f\n", tctx->stat_num_shift ? (float)((float)tctx->stat_total_shift / (float)tctx->stat_num_shift) : 0);
#endif /* B2GC_COUNTERS */
}

/**
 * \brief   Function to get the user defined values for b2g algorithm from the
 *          config file 'suricata.yaml'
 */
static void B2gcGetConfig()
{
    ConfNode *b2g_conf;
    const char *hash_val = NULL;
    const char *bloom_val = NULL;
    const char *algo = NULL;

    /* init defaults */
    b2gc_hash_size = HASHSIZE_LOW;
    b2gc_hash_shift = B2GC_HASHSHIFT_LOW;
    b2gc_bloom_size = BLOOMSIZE_MEDIUM;
    b2g_func = B2GC_SEARCHFUNC;

    ConfNode *pm = ConfGetNode("pattern-matcher");

    if (pm != NULL) {

        TAILQ_FOREACH(b2g_conf, &pm->head, next) {
            if (strncmp(b2g_conf->val, "b2gc", 4) == 0) {

                algo = ConfNodeLookupChildValue
                        (b2g_conf->head.tqh_first, "algo");
                hash_val = ConfNodeLookupChildValue
                        (b2g_conf->head.tqh_first, "hash_size");
                bloom_val = ConfNodeLookupChildValue
                        (b2g_conf->head.tqh_first, "bf_size");

                if (algo != NULL) {
                    if (strcmp(algo, "B2gcSearch") == 0) {
                        b2g_func = B2gcSearch;
                    } else if (strcmp(algo, "B2gcSearchBNDMq") == 0) {
                        b2g_func = B2gcSearchBNDMq;
                    }
                }

                if (hash_val != NULL) {
                    b2gc_hash_size = MpmGetHashSize(hash_val);
                    switch (b2gc_hash_size) {
                        case HASHSIZE_LOWEST:
                            b2gc_hash_shift = B2GC_HASHSHIFT_LOWEST;
                            break;
                        case HASHSIZE_LOW:
                            b2gc_hash_shift = B2GC_HASHSHIFT_LOW;
                            break;
                        case HASHSIZE_MEDIUM:
                            b2gc_hash_shift = B2GC_HASHSHIFT_MEDIUM;
                            break;
                        case HASHSIZE_HIGH:
                            b2gc_hash_shift = B2GC_HASHSHIFT_HIGH;
                            break;
                        case HASHSIZE_HIGHER:
                            b2gc_hash_shift = B2GC_HASHSHIFT_HIGHER;
                            break;
                        case HASHSIZE_MAX:
                            b2gc_hash_shift = B2GC_HASHSHIFT_MAX;
                            break;
                    }
                }
                if (bloom_val != NULL)
                    b2gc_bloom_size = MpmGetBloomSize(bloom_val);

                SCLogDebug("hash size is %"PRIu32" and bloom size is %"PRIu32"",
                        b2gc_hash_size, b2gc_bloom_size);
            }
        }
    }
}

void B2gcInitCtx (MpmCtx *mpm_ctx)
{
    SCLogDebug("mpm_ctx %p, ctx %p", mpm_ctx, mpm_ctx->ctx);

    if (mpm_ctx->ctx != NULL)
        return;

    //BUG_ON(mpm_ctx->ctx != NULL);

    mpm_ctx->ctx = SCMalloc(sizeof(B2gcCtx));
    if (mpm_ctx->ctx == NULL) {
        exit(EXIT_FAILURE);
    }

    memset(mpm_ctx->ctx, 0, sizeof(B2gcCtx));

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += sizeof(B2gcCtx);

    /* Initialize the defaults value from the config file. The given check make
       sure that we query config file only once for config values */
    if (b2gc_hash_size == 0)
        B2gcGetConfig();

    /* initialize the hash we use to speed up pattern insertions */
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx->ctx;

    ctx->b2gc_init_hash = HashListTableInit(4096, B2gcHashPatternInitHash, B2gcHashPatternCompare, NULL);
    if (ctx->b2gc_init_hash == NULL) {
        exit(EXIT_FAILURE);
    }

    /* init defaults search functions */
    ctx->Search = b2g_func;

    SCReturn;
}

void B2gcDestroyCtx(MpmCtx *mpm_ctx)
{

    SCLogDebug("mpm_ctx %p", mpm_ctx);

    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx->ctx;
    if (ctx == NULL)
        return;

    if (ctx->b2gc_init_hash != NULL) {
        HashListTableFree(ctx->b2gc_init_hash);
    }

    if (ctx->B2GC != NULL) {
        SCFree(ctx->B2GC);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (sizeof(B2GC_TYPE) * ctx->hash_size);
    }

    if (ctx->ha != NULL) {
        SCFree(ctx->ha);
    }

    if (ctx->ha1 != NULL) {
        SCFree(ctx->ha1);
    }

    if (ctx->patterns != NULL) {
        SCFree(ctx->patterns);
    }

    if (ctx->patterns1 != NULL) {
        SCFree(ctx->patterns1);
    }

    if (ctx->bloom) {
        uint32_t h;
        for (h = 0; h < ctx->hash_size; h++) {
            if (ctx->bloom[h] == NULL)
                continue;

            mpm_ctx->memory_cnt -= BloomFilterMemoryCnt(ctx->bloom[h]);
            mpm_ctx->memory_size -= BloomFilterMemorySize(ctx->bloom[h]);

            BloomFilterFree(ctx->bloom[h]);
        }

        SCFree(ctx->bloom);

        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (sizeof(BloomFilter *) * ctx->hash_size);
    }

    if (ctx->pminlen) {
        SCFree(ctx->pminlen);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (sizeof(uint8_t) * ctx->hash_size);
    }

    SCFree(mpm_ctx->ctx);
    mpm_ctx->memory_cnt--;
    mpm_ctx->memory_size -= sizeof(B2gcCtx);
}

void B2gcThreadInitCtx(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx, uint32_t matchsize)
{
    memset(mpm_thread_ctx, 0, sizeof(MpmThreadCtx));

    if (sizeof(B2gcThreadCtx) > 0) { /* size can be null when optimized */
        mpm_thread_ctx->ctx = SCMalloc(sizeof(B2gcThreadCtx));
        if (mpm_thread_ctx->ctx == NULL) {
            exit(EXIT_FAILURE);
        }

        memset(mpm_thread_ctx->ctx, 0, sizeof(B2gcThreadCtx));

        mpm_thread_ctx->memory_cnt++;
        mpm_thread_ctx->memory_size += sizeof(B2gcThreadCtx);
    }
}

void B2gcThreadDestroyCtx(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx)
{
    B2gcThreadCtx *ctx = (B2gcThreadCtx *)mpm_thread_ctx->ctx;

    B2gcPrintSearchStats(mpm_thread_ctx);

    if (ctx != NULL) { /* can be NULL if B2gcThreadCtx is optimized to 0 */
        mpm_thread_ctx->memory_cnt--;
        mpm_thread_ctx->memory_size -= sizeof(B2gcThreadCtx);
        SCFree(mpm_thread_ctx->ctx);
    }
}

uint32_t B2gcSearchWrap(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx, PatternMatcherQueue *pmq, uint8_t *buf, uint16_t buflen)
{
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx->ctx;
    return ctx ? ctx->Search(mpm_ctx, mpm_thread_ctx, pmq, buf, buflen) : 0;
}

uint32_t B2gcSearchBNDMq(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx, PatternMatcherQueue *pmq, uint8_t *buf, uint16_t buflen)
{
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx->ctx;
#ifdef B2GC_COUNTERS
    B2gcThreadCtx *tctx = (B2gcThreadCtx *)mpm_thread_ctx->ctx;
#endif
    uint32_t pos = ctx->m - B2GC_Q + 1, matches = 0;
    B2GC_TYPE d;

    //printf("\n");
    //PrintRawDataFp(stdout, buf, buflen);

    SCLogDebug("buflen %"PRIu16", ctx->m %"PRIu32", pos %"PRIu32,
            buflen, ctx->m, pos);

    COUNT(tctx->stat_calls++);
    COUNT(tctx->stat_m_total+=ctx->m);

    if (buflen < ctx->m)
        return 0;

    while (pos <= (uint32_t)(buflen - B2GC_Q + 1)) {
        //uint16_t h = B2GC_HASH16(u8_tolower(buf[pos - 1]),u8_tolower(buf[pos]));
        uint16_t h = B2GC_HASH16(buf[pos - 1], buf[pos]);
        d = ctx->B2GC[h];

        if (d != 0) {
            COUNT(tctx->stat_d0++);
            uint32_t j = pos;
            uint32_t first = pos - (ctx->m - B2GC_Q + 1);

            do {
                j = j - 1;

                if (d >= (uint32_t)(1 << (ctx->m - 1))) {
                    if (j > first)
                        pos = j;
                    else {
                        /* get our patterns from the hash */
                        h = B2GC_HASH16(buf[j + ctx->m - 2], buf[j + ctx->m - 1]);
                        if (ctx->pminlen[h] > 0 && (buflen - j) >= ctx->pminlen[h] &&
                            BloomFilterTest(ctx->bloom[h], buf+pos-1, ctx->pminlen[h]) == 1)
                        {
                            uint32_t offset = ctx->ha[h];
                            SCLogDebug("offset %u, hash %u", offset, h);
                            do {
                                B2gcPatternHdr *hdr = (B2gcPatternHdr *)&ctx->patterns[offset];
                                //BUG_ON(hdr->len <= 1);
                                offset += hdr->np_offset;
                                SCLogDebug("next offset %u", offset);

                                if (hdr->len <= (buflen - j)) {
                                    if (hdr->flags & B2GC_FLAG_NOCASE) {
                                        uint8_t *pattern = (uint8_t *)hdr + sizeof(B2gcPatternHdr);
                                        //uint8_t *pattern = (uint8_t *)hdr + hdr->nc_offset;
                                        SCLogDebug("nocase compare");
#ifdef PRINTMATCH
                                        prt(pattern, hdr->len);printf("\n");
                                        prt(buf+pos-1, hdr->len);printf("\n");
#endif
                                        if (SCMemcmpLowercase(pattern, buf+pos-1, hdr->len) == 0) {
                                            matches += MpmVerifyMatch(mpm_thread_ctx, pmq, hdr->id);
                                        }
                                    } else {
                                        uint8_t *pattern = (uint8_t *)hdr + sizeof(B2gcPatternHdr);
                                        SCLogDebug("case sensitive compare");
#ifdef PRINTMATCH
                                        prt(pattern, hdr->len);printf("\n");
                                        prt(buf+pos-1, hdr->len);printf("\n");
#endif
                                        if (SCMemcmp(pattern, buf+pos-1, hdr->len) == 0) {
                                            matches += MpmVerifyMatch(mpm_thread_ctx, pmq, hdr->id);
                                        }
                                    }
                                }

                                if (hdr->flags & B2GC_FLAG_FINAL) {
                                    SCLogDebug("final flag set, done matching");
                                    break;
                                }
                            } while(1);
                        }
                    }
                }

                if (j == 0) {
                    break;
                }

                h = B2GC_HASH16(buf[j - 1], buf[j]);
                d = (d << 1) & ctx->B2GC[h];
            } while (d != 0);
        }
        COUNT(tctx->stat_num_shift++);
        COUNT(tctx->stat_total_shift += (ctx->m - B2GC_Q + 1));
        pos = pos + ctx->m - B2GC_Q + 1;

        SCLogDebug("pos %"PRIu32"", pos);
    }

    SCLogDebug("matches %"PRIu32"", matches);
    return matches;
}

uint32_t B2gcSearch(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx, PatternMatcherQueue *pmq, uint8_t *buf, uint16_t buflen)
{
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx->ctx;
#ifdef B2GC_COUNTERS
    B2gcThreadCtx *tctx = (B2gcThreadCtx *)mpm_thread_ctx->ctx;
#endif
    uint32_t pos = 0, matches = 0;
    B2GC_TYPE d;
    uint32_t j;

    COUNT(tctx->stat_calls++);
    COUNT(tctx->stat_m_total+=ctx->m);

    if (buflen < ctx->m)
        return 0;

    while (pos <= (buflen - ctx->m)) {
        j = ctx->m - 1;
        d = ~0;

        do {
            uint16_t h = B2GC_HASH16(u8_tolower(buf[pos + j - 1]),u8_tolower(buf[pos + j]));
            d = ((d << 1) & ctx->B2GC[h]);
            j = j - 1;
        } while (d != 0 && j != 0);

        /* (partial) match, move on to verification */
        if (d != 0) {
            COUNT(tctx->stat_d0++);
            //printf("output at pos %" PRIu32 ": ", pos); prt(buf + pos, ctx->m); printf("\n");

#if 0
            /* get our patterns from the hash */
            uint16_t h = B2GC_HASH16(u8_tolower(buf[pos + ctx->m - 2]),u8_tolower(buf[pos + ctx->m - 1]));
            B2gcPattern *hi = ctx->hash[h], *thi;
            for (thi = hi; thi != NULL; thi = thi->next) {
                COUNT(tctx->stat_d0_hashloop++);
                //B2gcPattern *p = ctx->parray[thi->idx];

                if (buflen - pos < thi->len)
                    continue;

                if (thi->flags & MPM_PATTERN_FLAG_NOCASE) {

                    if (memcmp_lowercase(thi->ci, buf+pos, thi->len) == 0) {
                        COUNT(tctx->stat_loop_match++);

                        matches += MpmVerifyMatch(mpm_thread_ctx, pmq, thi->id);
                    } else {
                        COUNT(tctx->stat_loop_no_match++);
                    }
                } else {
                    if (memcmp(thi->cs, buf+pos, thi->len) == 0) {
                        COUNT(tctx->stat_loop_match++);

                        matches += MpmVerifyMatch(mpm_thread_ctx, pmq, thi->id);
                    } else {
                        COUNT(tctx->stat_loop_no_match++);
                    }
                }
            }
skip_loop:
            //pos = pos + ctx->s0;
            pos = pos + 1;
#endif
        } else {
            COUNT(tctx->stat_num_shift++);
            COUNT(tctx->stat_total_shift += (j + 1));

            pos = pos + j + 1;
        }
    }

    //printf("Total matches %" PRIu32 "\n", matches);
    return matches;
}

uint32_t B2gcSearch1(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx, PatternMatcherQueue *pmq, uint8_t *buf, uint16_t buflen)
{
    SCEnter();

    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx->ctx;
    uint8_t *bufmin = buf;
    uint8_t *bufend = buf + buflen - 1;
    uint32_t cnt = 0;

    if (buflen == 0)
        SCReturnUInt(0);

    //printf("BUF "); prt(buf,buflen); printf("\n");

    while (buf <= bufend) {
        uint8_t h = u8_tolower(*buf);
        uint16_t offset = ctx->ha1[h];
        SCLogDebug("offset %u, h %02X, buf %02X", offset, h, *buf);

        if (offset > 0) {
            do {
                B2gcPattern1 *hdr = (B2gcPattern1 *)&ctx->patterns1[offset];
                offset += (sizeof(B2gcPattern1));

                SCLogDebug("hdr flags %02x, id %u, pat %02X", hdr->flags, hdr->id, hdr->pat);

                if (hdr->flags & B2GC_FLAG_NOCASE) {
                    SCLogDebug("nocase compare, %02X", *buf);

                    cnt += MpmVerifyMatch(mpm_thread_ctx, pmq, hdr->id);
                } else {
                    SCLogDebug("case sensitive compare, %02X", *buf);

                    if (*buf == hdr->pat) {
                        cnt += MpmVerifyMatch(mpm_thread_ctx, pmq, hdr->id);
                    }
                }

                if (hdr->flags & B2GC_FLAG_FINAL)
                    break;
            } while(1);
        }
        buf += 1;
    }

    //printf("B2gcSearch1: after 1byte cnt %" PRIu32 "\n", cnt);
    if (ctx->pat_x_cnt) {
        cnt += ctx->MBSearch(mpm_ctx, mpm_thread_ctx, pmq, bufmin, buflen);
    }
    SCReturnUInt(cnt);
}

/*
 * TESTS
 */

#ifdef UNITTESTS
static int B2gcTestMacro01 (void)
{
    int result = 1;

    B2gcPatternHdr a;
    B2gcPatternHdr *b = &a;

    memset(&a, 0xff, sizeof(a));

    printf("ID %u\n", B2GC_GET_ID(b));
    printf("FLAGS %u\n", B2GC_GET_FLAGS(b));
    printf("LEN %u\n", B2GC_GET_LEN(b));

    return result;
}

static int B2gcTestInit01 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmInitCtx(&mpm_ctx, MPM_B2GC);
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0); /* 1 match */

    B2gcPreparePatterns(&mpm_ctx);

    if (ctx->m == 4)
        result = 1;
    else
        printf("4 != %" PRIu32 " ", ctx->m);

    B2gcDestroyCtx(&mpm_ctx);
    return result;
}

#if 0
static int B2gcTestS0Init01 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2GC);
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0); /* 1 match */

    B2gcPreparePatterns(&mpm_ctx);

    if (ctx->s0 == 4)
        result = 1;
    else
        printf("4 != %" PRIu32 " ", ctx->s0);

    B2gcDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gcTestS0Init02 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2GC);
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0); /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"cdef", 4, 0, 0, 1, 0); /* 1 match */

    B2gcPreparePatterns(&mpm_ctx);

    if (ctx->s0 == 2)
        result = 1;
    else
        printf("2 != %" PRIu32 " ", ctx->s0);

    B2gcDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gcTestS0Init03 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2GC);
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0); /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"bcde", 4, 0, 0, 1, 0); /* 1 match */

    B2gcPreparePatterns(&mpm_ctx);

    if (ctx->s0 == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ", ctx->s0);

    B2gcDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gcTestS0Init04 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2GC);
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abab", 4, 0, 0, 0, 0); /* 1 match */

    B2gcPreparePatterns(&mpm_ctx);

    if (ctx->s0 == 2)
        result = 1;
    else
        printf("2 != %" PRIu32 " ", ctx->s0);

    B2gcDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gcTestS0Init05 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2GC);
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcab", 5, 0, 0, 0, 0); /* 1 match */

    B2gcPreparePatterns(&mpm_ctx);

    if (ctx->s0 == 3)
        result = 1;
    else
        printf("3 != %" PRIu32 " ", ctx->s0);

    B2gcDestroyCtx(&mpm_ctx);
    return result;
}
#endif

static int B2gcTestSearch01 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2GC);
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0); /* 1 match */

    B2gcPreparePatterns(&mpm_ctx);
    B2gcThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"abcdefghjiklmnopqrstuvwxyz", 26);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gcThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gcDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gcTestSearch02 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2GC);
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abce", 4, 0, 0, 0, 0, 0); /* 1 match */

    B2gcPreparePatterns(&mpm_ctx);
    B2gcThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"abcdefghjiklmnopqrstuvwxyz", 26);

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ",cnt);

    B2gcThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gcDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gcTestSearch03 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2GC);
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0); /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"bcde", 4, 0, 0, 1, 0, 0); /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"fghj", 4, 0, 0, 2, 0, 0); /* 1 match */

    B2gcPreparePatterns(&mpm_ctx);
    B2gcThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 3 /* 3 patterns */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"abcdefghjiklmnopqrstuvwxyz", 26);

    if (cnt == 3)
        result = 1;
    else
        printf("3 != %" PRIu32 " ",cnt);

    B2gcThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gcDestroyCtx(&mpm_ctx);
    return result;
}

/* test patterns longer than 'm'. M is 4 here. */
static int B2gcTestSearch04 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2GC);
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0); /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"bcdegh", 6, 0, 0, 1, 0, 0); /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"fghjxyz", 7, 0, 0, 2, 0, 0); /* 1 match */

    B2gcPreparePatterns(&mpm_ctx);
    B2gcThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 3 /* 3 patterns */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"abcdefghjiklmnopqrstuvwxyz", 26);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gcThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gcDestroyCtx(&mpm_ctx);
    return result;
}

/* case insensitive test patterns longer than 'm'. M is 4 here. */
static int B2gcTestSearch05 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2GC);
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx.ctx;

    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"ABCD", 4, 0, 0, 0, 0, 0); /* 1 match */
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"bCdEfG", 6, 0, 0, 1, 0, 0); /* 1 match */
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"fghJikl", 7, 0, 0, 2, 0, 0); /* 1 match */

    B2gcPreparePatterns(&mpm_ctx);
    B2gcThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 3 /* 3 patterns */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"abcdefghjiklmnopqrstuvwxyz", 26);

    if (cnt == 3)
        result = 1;
    else
        printf("3 != %" PRIu32 " ",cnt);

    B2gcThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gcDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gcTestSearch05a (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2GC);
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx.ctx;

    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"ABCD", 4, 0, 0, 0, 0, 0); /* 1 match */
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"bCdEfG", 6, 0, 0, 1, 0, 0); /* 1 match */
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"fghJikl", 7, 0, 0, 2, 0, 0); /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abCD", 4, 0, 0, 3, 0, 0); /* no match */
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"abcD", 4, 0, 0, 4, 0, 0); /* 1 match */
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"abCd", 4, 0, 0, 5, 0, 0); /* 1 match */

    B2gcPreparePatterns(&mpm_ctx);
    B2gcThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 6 /* 6 patterns */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"abcdefghjiklmnopqrstuvwxyz", 26);

    if (cnt == 5)
        result = 1;
    else
        printf("5 != %" PRIu32 " ",cnt);

    B2gcThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gcDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gcTestSearch05b (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2GC);
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx.ctx;

    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"ABCD", 4, 0, 0, 0, 0, 0); /* 1 match */
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 1, 0, 0); /* 1 match */
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"abcD", 4, 0, 0, 2, 0, 0); /* 1 match */
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"abCd", 4, 0, 0, 3, 0, 0); /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 4, 0, 0); /* 1 match */
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"abXD", 4, 0, 0, 5, 0, 0); /* 0 match */

    B2gcPreparePatterns(&mpm_ctx);
    B2gcThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 6 /* 6 patterns */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"abcdefghjiklmnopqrstuvwxyz", 26);

    if (cnt == 5)
        result = 1;
    else
        printf("5 != %" PRIu32 " ",cnt);

    B2gcThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gcDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gcTestSearch05c (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2GC);
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx.ctx;

    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0); /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 1, 0, 0); /* 1 match */

    B2gcPreparePatterns(&mpm_ctx);
    B2gcThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 2 /* 6 patterns */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"abcd", 4);

    if (cnt == 2)
        result = 1;
    else
        printf("2 != %" PRIu32 " ",cnt);

    B2gcThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gcDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gcTestSearch05d (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2GC);
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx.ctx;

    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0); /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"ABCD", 4, 0, 0, 1, 0, 0); /* 1 match */

    B2gcPreparePatterns(&mpm_ctx);
    B2gcThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 2 /* 6 patterns */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"ABCD", 4);

    if (cnt == 2)
        result = 1;
    else
        printf("2 != %" PRIu32 " ",cnt);

    B2gcThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gcDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gcTestSearch06 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2GC);
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0); /* 1 match */

    B2gcPreparePatterns(&mpm_ctx);
    B2gcThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"abcd", 4);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gcThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gcDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gcTestSearch06a (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2GC);
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"a", 1, 0, 0, 0, 0, 0); /* 1 match */

    B2gcPreparePatterns(&mpm_ctx);
    B2gcThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"abcd", 4);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gcThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gcDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gcTestSearch07 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2GC);
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"A", 1, 0, 0, 0, 0, 0); /* should match 30 times */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AA", 2, 0, 0, 1, 0, 0); /* should match 29 times */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AAA", 3, 0, 0, 2, 0, 0); /* should match 28 times */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AAAAA", 5, 0, 0, 3, 0, 0); /* 26 */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AAAAAAAAAA", 10, 0, 0, 4, 0, 0); /* 21 */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 30, 0, 0, 5, 0, 0); /* 1 */
    /* total matches: 135 */

    B2gcPreparePatterns(&mpm_ctx);
    B2gcThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 6 /* 6 patterns */);

    uint32_t cnt;
    int i;
    for (i = 0; i<100000;i++)
        cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 30);

    if (cnt == 135)
        result = 1;
    else
        printf("135 != %" PRIu32 " ",cnt);

    B2gcThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gcDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gcTestSearch07a (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2GC);
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"A", 1, 0, 0, 0, 0, 0); /* should match 30 times */

    B2gcPreparePatterns(&mpm_ctx);
    B2gcThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 6 patterns */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 30);

    if (cnt == 30)
        result = 1;
    else
        printf("30 != %" PRIu32 " ",cnt);

    B2gcThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gcDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gcTestSearch08 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2GC);
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0); /* 1 match */

    B2gcPreparePatterns(&mpm_ctx);
    B2gcThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"a", 1);

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ",cnt);

    B2gcThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gcDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gcTestSearch09 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2GC);
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"ab", 2, 0, 0, 0, 0, 0); /* 1 match */

    B2gcPreparePatterns(&mpm_ctx);
    B2gcThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"ab", 2);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gcThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gcDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gcTestSearch10 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2GC);
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcdefgh", 8, 0, 0, 0, 0, 0); /* 1 match */

    B2gcPreparePatterns(&mpm_ctx);
    B2gcThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    char *buf = "01234567890123456789012345678901234567890123456789"
                "01234567890123456789012345678901234567890123456789"
                "abcdefgh"
                "01234567890123456789012345678901234567890123456789"
                "01234567890123456789012345678901234567890123456789";
    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)buf, strlen(buf));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gcThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gcDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gcTestSearch11 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2GC);
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0); /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcde", 5, 0, 0, 1, 0, 0); /* 1 match */

    B2gcPreparePatterns(&mpm_ctx);
    B2gcThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 2 /* 2 patterns */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"abcdefghijklmnopqrstuvwxyz", 26);

    if (cnt == 2)
        result = 1;
    else
        printf("2 != %" PRIu32 " ",cnt);

    B2gcThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gcDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gcTestSearch12 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2GC);
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"wxyz", 4, 0, 0, 0, 0, 0); /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"vwxyz", 5, 0, 0, 1, 0, 0); /* 1 match */

    B2gcPreparePatterns(&mpm_ctx);
    B2gcThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 2 /* 2 patterns */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"abcdefghijklmnopqrstuvwxyz", 26);

    if (cnt == 2)
        result = 1;
    else
        printf("2 != %" PRIu32 " ",cnt);

    B2gcThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gcDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gcTestSearch13 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2GC);
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcdefghijklmnopqrstuvwxyzABCD", 30, 0, 0, 0, 0, 0); /* 1 match */

    B2gcPreparePatterns(&mpm_ctx);
    B2gcThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"abcdefghijklmnopqrstuvwxyzABCD", 30);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gcThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gcDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gcTestSearch14 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2GC);
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcdefghijklmnopqrstuvwxyzABCDE", 31, 0, 0, 0, 0, 0); /* 1 match */

    B2gcPreparePatterns(&mpm_ctx);
    B2gcThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"abcdefghijklmnopqrstuvwxyzABCDE", 31);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gcThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gcDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gcTestSearch15 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2GC);
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcdefghijklmnopqrstuvwxyzABCDEF", 32, 0, 0, 0, 0, 0); /* 1 match */

    B2gcPreparePatterns(&mpm_ctx);
    B2gcThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"abcdefghijklmnopqrstuvwxyzABCDEF", 32);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gcThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gcDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gcTestSearch16 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2GC);
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcdefghijklmnopqrstuvwxyzABC", 29, 0, 0, 0, 0, 0); /* 1 match */

    B2gcPreparePatterns(&mpm_ctx);
    B2gcThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"abcdefghijklmnopqrstuvwxyzABC", 29);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gcThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gcDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gcTestSearch17 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2GC);
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcdefghijklmnopqrstuvwxyzAB", 28, 0, 0, 0, 0, 0); /* 1 match */

    B2gcPreparePatterns(&mpm_ctx);
    B2gcThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"abcdefghijklmnopqrstuvwxyzAB", 28);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gcThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gcDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gcTestSearch18 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2GC);
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcde""fghij""klmno""pqrst""uvwxy""z", 26, 0, 0, 0, 0, 0); /* 1 match */

    B2gcPreparePatterns(&mpm_ctx);
    B2gcThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"abcde""fghij""klmno""pqrst""uvwxy""z", 26);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gcThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gcDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gcTestSearch19 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2GC);
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 30, 0, 0, 0, 0, 0); /* 1 */

    B2gcPreparePatterns(&mpm_ctx);
    B2gcThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 patterns */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 30);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gcThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gcDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gcTestSearch20 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2GC);
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AAAAA""AAAAA""AAAAA""AAAAA""AAAAA""AAAAA""AA", 32, 0, 0, 0, 0, 0); /* 1 */
    //MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 32, 0, 0, 0, 0, 0); /* 1 */

    B2gcPreparePatterns(&mpm_ctx);
    B2gcThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 patterns */);

    //uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 32);
    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"AAAAA""AAAAA""AAAAA""AAAAA""AAAAA""AAAAA""AA", 32);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gcThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gcDestroyCtx(&mpm_ctx);
    return result;
}

static int B2gcTestSearch21 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2GC);
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AA", 2, 0, 0, 0, 0, 0); /* 1 */

    B2gcPreparePatterns(&mpm_ctx);
    B2gcThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 patterns */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"AA", 2);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B2gcThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gcDestroyCtx(&mpm_ctx);
    return result;
}
#endif /* UNITTESTS */

#if 0
static int B2gcTestSearchXX (void)
{
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B2GC);
    B2gcCtx *ctx = (B2gcCtx *)mpm_ctx.ctx;

    FILE *fp = fopen("/usr/share/dict/words", "r");
    if (fp == NULL)
        exit(1);

    char *word;
    char line[128];
    int w = 0;
    int w_max = 4000;

    while((word = fgets(line, sizeof(line), fp)) != NULL) {
        word[strlen(word) - 1] = '\0';

        MpmAddPatternCS(&mpm_ctx, (uint8_t *)word, strlen(word), 0, 0, (uint32_t)w, 0, 0);

        w++;

        if (w_max == w)
            break;
    }

    B2gcPreparePatterns(&mpm_ctx);
    B2gcThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 patterns */);

    char *text = "Yes this is a text, it is not very long. But, it is still sufficient for testing our search! "
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "flkflkjjoijda893ur9r89h98hf9shflj;adm.,amnd,mna,mndabdayyugeq9e8u0q90-euajd;lsaldakljdlkajdl"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "we're adding a lot more text lines etc."
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "dlajd01438798749023749792739479ye9q8eu3291739847983274987e928u928eu98u3298eu982u938383888888 "
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "flkflkjjoijda893ur9r89h98hf9shflj;adm.,amnd,mna,mndabdayyugeq9e8u0q90-euajd;lsaldakljdlkajdl"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "we're adding a lot more text lines etc."
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "dlajd01438798749023749792739479ye9q8eu3291739847983274987e928u928eu98u3298eu982u938383888888 "
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "flkflkjjoijda893ur9r89h98hf9shflj;adm.,amnd,mna,mndabdayyugeq9e8u0q90-euajd;lsaldakljdlkajdl"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "we're adding a lot more text lines etc."
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "dlajd01438798749023749792739479ye9q8eu3291739847983274987e928u928eu98u3298eu982u938383888888 "
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "flkflkjjoijda893ur9r89h98hf9shflj;adm.,amnd,mna,mndabdayyugeq9e8u0q90-euajd;lsaldakljdlkajdl"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "we're adding a lot more text lines etc."
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "dlajd01438798749023749792739479ye9q8eu3291739847983274987e928u928eu98u3298eu982u938383888888 "
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "flkflkjjoijda893ur9r89h98hf9shflj;adm.,amnd,mna,mndabdayyugeq9e8u0q90-euajd;lsaldakljdlkajdl"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "we're adding a lot more text lines etc."
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "dlajd01438798749023749792739479ye9q8eu3291739847983274987e928u928eu98u3298eu982u938383888888 "
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "flkflkjjoijda893ur9r89h98hf9shflj;adm.,amnd,mna,mndabdayyugeq9e8u0q90-euajd;lsaldakljdlkajdl"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "we're adding a lot more text lines etc."
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "dlajd01438798749023749792739479ye9q8eu3291739847983274987e928u928eu98u3298eu982u938383888888 "
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "flkflkjjoijda893ur9r89h98hf9shflj;adm.,amnd,mna,mndabdayyugeq9e8u0q90-euajd;lsaldakljdlkajdl"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "we're adding a lot more text lines etc."
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "dlajd01438798749023749792739479ye9q8eu3291739847983274987e928u928eu98u3298eu982u938383888888 "
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "flkflkjjoijda893ur9r89h98hf9shflj;adm.,amnd,mna,mndabdayyugeq9e8u0q90-euajd;lsaldakljdlkajdl"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "we're adding a lot more text lines etc."
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "dlajd01438798749023749792739479ye9q8eu3291739847983274987e928u928eu98u3298eu982u938383888888 "
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "flkflkjjoijda893ur9r89h98hf9shflj;adm.,amnd,mna,mndabdayyugeq9e8u0q90-euajd;lsaldakljdlkajdl"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "we're adding a lot more text lines etc."
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "dlajd01438798749023749792739479ye9q8eu3291739847983274987e928u928eu98u3298eu982u938383888888 "
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "flkflkjjoijda893ur9r89h98hf9shflj;adm.,amnd,mna,mndabdayyugeq9e8u0q90-euajd;lsaldakljdlkajdl"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "we're adding a lot more text lines etc."
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "dlajd01438798749023749792739479ye9q8eu3291739847983274987e928u928eu98u3298eu982u938383888888 "
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "flkflkjjoijda893ur9r89h98hf9shflj;adm.,amnd,mna,mndabdayyugeq9e8u0q90-euajd;lsaldakljdlkajdl"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "we're adding a lot more text lines etc."
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "dlajd01438798749023749792739479ye9q8eu3291739847983274987e928u928eu98u3298eu982u938383888888 "
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "flkflkjjoijda893ur9r89h98hf9shflj;adm.,amnd,mna,mndabdayyugeq9e8u0q90-euajd;lsaldakljdlkajdl"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "we're adding a lot more text lines etc."
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "dlajd01438798749023749792739479ye9q8eu3291739847983274987e928u928eu98u3298eu982u938383888888 "
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "flkflkjjoijda893ur9r89h98hf9shflj;adm.,amnd,mna,mndabdayyugeq9e8u0q90-euajd;lsaldakljdlkajdl"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "we're adding a lot more text lines etc."
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "dlajd01438798749023749792739479ye9q8eu3291739847983274987e928u928eu98u3298eu982u938383888888 "
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "flkflkjjoijda893ur9r89h98hf9shflj;adm.,amnd,mna,mndabdayyugeq9e8u0q90-euajd;lsaldakljdlkajdl"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "we're adding a lot more text lines etc."
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "dlajd01438798749023749792739479ye9q8eu3291739847983274987e928u928eu98u3298eu982u938383888888 "
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "flkflkjjoijda893ur9r89h98hf9shflj;adm.,amnd,mna,mndabdayyugeq9e8u0q90-euajd;lsaldakljdlkajdl"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "we're adding a lot more text lines etc."
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "dlajd01438798749023749792739479ye9q8eu3291739847983274987e928u928eu98u3298eu982u938383888888 "
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "flkflkjjoijda893ur9r89h98hf9shflj;adm.,amnd,mna,mndabdayyugeq9e8u0q90-euajd;lsaldakljdlkajdl"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "we're adding a lot more text lines etc."
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "dlajd01438798749023749792739479ye9q8eu3291739847983274987e928u928eu98u3298eu982u938383888888 "
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "flkflkjjoijda893ur9r89h98hf9shflj;adm.,amnd,mna,mndabdayyugeq9e8u0q90-euajd;lsaldakljdlkajdl"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "we're adding a lot more text lines etc."
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "dlajd01438798749023749792739479ye9q8eu3291739847983274987e928u928eu98u3298eu982u938383888888 "
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "flkflkjjoijda893ur9r89h98hf9shflj;adm.,amnd,mna,mndabdayyugeq9e8u0q90-euajd;lsaldakljdlkajdl"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "we're adding a lot more text lines etc."
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "dlajd01438798749023749792739479ye9q8eu3291739847983274987e928u928eu98u3298eu982u938383888888 "
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "flkflkjjoijda893ur9r89h98hf9shflj;adm.,amnd,mna,mndabdayyugeq9e8u0q90-euajd;lsaldakljdlkajdl"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "we're adding a lot more text lines etc."
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "dlajd01438798749023749792739479ye9q8eu3291739847983274987e928u928eu98u3298eu982u938383888888 "
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "flkflkjjoijda893ur9r89h98hf9shflj;adm.,amnd,mna,mndabdayyugeq9e8u0q90-euajd;lsaldakljdlkajdl"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "we're adding a lot more text lines etc."
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "dlajd01438798749023749792739479ye9q8eu3291739847983274987e928u928eu98u3298eu982u938383888888 "
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "flkflkjjoijda893ur9r89h98hf9shflj;adm.,amnd,mna,mndabdayyugeq9e8u0q90-euajd;lsaldakljdlkajdl"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "we're adding a lot more text lines etc."
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "dlajd01438798749023749792739479ye9q8eu3291739847983274987e928u928eu98u3298eu982u938383888888 "
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "flkflkjjoijda893ur9r89h98hf9shflj;adm.,amnd,mna,mndabdayyugeq9e8u0q90-euajd;lsaldakljdlkajdl"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "we're adding a lot more text lines etc."
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "dlajd01438798749023749792739479ye9q8eu3291739847983274987e928u928eu98u3298eu982u938383888888 "
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "flkflkjjoijda893ur9r89h98hf9shflj;adm.,amnd,mna,mndabdayyugeq9e8u0q90-euajd;lsaldakljdlkajdl"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "we're adding a lot more text lines etc."
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "dlajd01438798749023749792739479ye9q8eu3291739847983274987e928u928eu98u3298eu982u938383888888 "
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        "Bjdhfahflkahsf;phf[hfihasfkhsfkjhalhflkafljhfkhakhfkahfkahfkjhdkffkjhafkhafkjakjfhkjahf;aj;jh";
    uint32_t len = strlen(text) - 1;

    int i;
    uint32_t cnt;
    for (i = 0; i < 100; i++) {
        cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)text, len);
    }
    printf("cnt %u ", cnt);

    B2gcThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B2gcDestroyCtx(&mpm_ctx);
    fclose(fp);

    return 1;
}
#endif

void B2gcRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("B2gcTestMacro01", B2gcTestMacro01, 1);
    UtRegisterTest("B2gcTestInit01", B2gcTestInit01, 1);
/*
    UtRegisterTest("B2gcTestS0Init01", B2gcTestS0Init01, 1);
    UtRegisterTest("B2gcTestS0Init02", B2gcTestS0Init02, 1);
    UtRegisterTest("B2gcTestS0Init03", B2gcTestS0Init03, 1);
    UtRegisterTest("B2gcTestS0Init04", B2gcTestS0Init04, 1);
    UtRegisterTest("B2gcTestS0Init05", B2gcTestS0Init05, 1);
*/
    UtRegisterTest("B2gcTestSearch01", B2gcTestSearch01, 1);
    UtRegisterTest("B2gcTestSearch02", B2gcTestSearch02, 1);
    UtRegisterTest("B2gcTestSearch03", B2gcTestSearch03, 1);
    UtRegisterTest("B2gcTestSearch04", B2gcTestSearch04, 1);
    UtRegisterTest("B2gcTestSearch05", B2gcTestSearch05, 1);
    UtRegisterTest("B2gcTestSearch05a", B2gcTestSearch05a, 1);
    UtRegisterTest("B2gcTestSearch05b", B2gcTestSearch05b, 1);
    UtRegisterTest("B2gcTestSearch05c", B2gcTestSearch05c, 1);
    UtRegisterTest("B2gcTestSearch05d", B2gcTestSearch05d, 1);
    UtRegisterTest("B2gcTestSearch06", B2gcTestSearch06, 1);
    UtRegisterTest("B2gcTestSearch06a", B2gcTestSearch06a, 1);
    UtRegisterTest("B2gcTestSearch07", B2gcTestSearch07, 1);
    UtRegisterTest("B2gcTestSearch07a", B2gcTestSearch07a, 1);
    UtRegisterTest("B2gcTestSearch08", B2gcTestSearch08, 1);
    UtRegisterTest("B2gcTestSearch09", B2gcTestSearch09, 1);
    UtRegisterTest("B2gcTestSearch10", B2gcTestSearch10, 1);
    UtRegisterTest("B2gcTestSearch11", B2gcTestSearch11, 1);
    UtRegisterTest("B2gcTestSearch12", B2gcTestSearch12, 1);
    UtRegisterTest("B2gcTestSearch13", B2gcTestSearch13, 1);
    UtRegisterTest("B2gcTestSearch14", B2gcTestSearch14, 1);
    UtRegisterTest("B2gcTestSearch15", B2gcTestSearch15, 1);
    UtRegisterTest("B2gcTestSearch16", B2gcTestSearch16, 1);
    UtRegisterTest("B2gcTestSearch17", B2gcTestSearch17, 1);
    UtRegisterTest("B2gcTestSearch18", B2gcTestSearch18, 1);
    UtRegisterTest("B2gcTestSearch19", B2gcTestSearch19, 1);
    UtRegisterTest("B2gcTestSearch20", B2gcTestSearch20, 1);
    UtRegisterTest("B2gcTestSearch21", B2gcTestSearch21, 1);
/*
    UtRegisterTest("B2gcTestSearchXX", B2gcTestSearchXX, 1);
*/
#endif /* UNITTESTS */
}


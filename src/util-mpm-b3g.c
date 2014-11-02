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
 * 3 gram implementation of the (S)BNDMq pattern matching algorithm.
 *
 * Ideas:
 *  - B3g does a full match in the search of up to 'm' characters,
 *    in case of a case insensitive search we could say it's match if
 *    the pattern is of len 'm' or just compare the rest of the chars.
 *
 * \todo Try to get the S0 calculation right.
 */

#include "suricata-common.h"
#include "suricata.h"
#include "util-bloomfilter.h"
#include "util-mpm-b3g.h"
#include "util-unittest.h"
#include "conf.h"
#include "util-debug.h"
#include "util-memcpy.h"

#define INIT_HASH_SIZE 65536

#ifdef B3G_COUNTERS
#define COUNT(counter) \
        (counter)
#else
#define COUNT(counter)
#endif /* B3G_COUNTERS */

static uint32_t b3g_hash_size = 0;
static uint32_t b3g_bloom_size = 0;
static uint8_t b3g_hash_shift = 0;
static uint8_t b3g_hash_shift2 = 0;
static void *b3g_func;

#define B3G_HASH(a,b,c)   (((a) << b3g_hash_shift) | (b) << (b3g_hash_shift2) |(c))

void B3gInitCtx (MpmCtx *);
void B3gThreadInitCtx(MpmCtx *, MpmThreadCtx *, uint32_t);
void B3gDestroyCtx(MpmCtx *);
void B3gThreadDestroyCtx(MpmCtx *, MpmThreadCtx *);
int B3gAddPatternCI(MpmCtx *, uint8_t *, uint16_t, uint16_t, uint16_t, uint32_t, SigIntId, uint8_t);
int B3gAddPatternCS(MpmCtx *, uint8_t *, uint16_t, uint16_t, uint16_t, uint32_t, SigIntId, uint8_t);
int B3gPreparePatterns(MpmCtx *);
uint32_t B3gSearchWrap(MpmCtx *, MpmThreadCtx *, PatternMatcherQueue *, uint8_t *, uint16_t);
uint32_t B3gSearch1(MpmCtx *, MpmThreadCtx *, PatternMatcherQueue *, uint8_t *, uint16_t);
uint32_t B3gSearch2(MpmCtx *, MpmThreadCtx *, PatternMatcherQueue *, uint8_t *, uint16_t);
uint32_t B3gSearch12(MpmCtx *, MpmThreadCtx *, PatternMatcherQueue *, uint8_t *, uint16_t);
uint32_t B3gSearch(MpmCtx *, MpmThreadCtx *, PatternMatcherQueue *, uint8_t *, uint16_t);
uint32_t B3gSearchBNDMq(MpmCtx *, MpmThreadCtx *, PatternMatcherQueue *, uint8_t *, uint16_t);
void B3gPrintInfo(MpmCtx *);
void B3gPrintSearchStats(MpmThreadCtx *);
void B3gRegisterTests(void);

/** \todo XXX Unused??? */
#if 0
static void prt (uint8_t *buf, uint16_t buflen)
{
    uint16_t i;

    for (i = 0; i < buflen; i++) {
        if (isprint(buf[i])) printf("%c", buf[i]);
        else                 printf("\\x%" PRIX32, buf[i]);
    }
    //printf("\n");
}
#endif

void B3gPrintInfo(MpmCtx *mpm_ctx)
{
    B3gCtx *ctx = (B3gCtx *)mpm_ctx->ctx;

    printf("MPM B3g Information:\n");
    printf("Memory allocs:   %" PRIu32 "\n", mpm_ctx->memory_cnt);
    printf("Memory alloced:  %" PRIu32 "\n", mpm_ctx->memory_size);
    printf(" Sizeofs:\n");
    printf("  MpmCtx         %" PRIuMAX "\n", (uintmax_t)sizeof(MpmCtx));
    printf("  B3gCtx:         %" PRIuMAX "\n", (uintmax_t)sizeof(B3gCtx));
    printf("  B3gPattern      %" PRIuMAX "\n", (uintmax_t)sizeof(B3gPattern));
    printf("  B3gHashItem     %" PRIuMAX "\n", (uintmax_t)sizeof(B3gHashItem));
    printf("Unique Patterns: %" PRIu32 "\n", mpm_ctx->pattern_cnt);
    printf("Smallest:        %" PRIu32 "\n", mpm_ctx->minlen);
    printf("Largest:         %" PRIu32 "\n", mpm_ctx->maxlen);
    printf("Hash size:       %" PRIu32 "\n", ctx->hash_size);
    printf("\n");
}

static inline B3gPattern *B3gAllocPattern(MpmCtx *mpm_ctx)
{
    B3gPattern *p = SCMalloc(sizeof(B3gPattern));
    if (unlikely(p == NULL))
        return NULL;
    memset(p,0,sizeof(B3gPattern));

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += sizeof(B3gPattern);
    return p;
}

static inline B3gHashItem *
B3gAllocHashItem(MpmCtx *mpm_ctx)
{
    B3gHashItem *hi = SCMalloc(sizeof(B3gHashItem));
    if (unlikely(hi == NULL))
        return NULL;
    memset(hi,0,sizeof(B3gHashItem));

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += sizeof(B3gHashItem);
    return hi;
}

static void B3gHashFree(MpmCtx *mpm_ctx, B3gHashItem *hi)
{
    if (hi == NULL)
        return;

    B3gHashItem *t = hi->nxt;
    B3gHashFree(mpm_ctx, t);

    mpm_ctx->memory_cnt--;
    mpm_ctx->memory_size -= sizeof(B3gHashItem);
    SCFree(hi);
}

/*
 * INIT HASH START
 */
static inline uint32_t B3gInitHash(B3gPattern *p)
{
    uint32_t hash = p->len * p->cs[0];
    if (p->len > 1)
        hash += p->cs[1];

    return (hash % INIT_HASH_SIZE);
}

static inline uint32_t B3gInitHashRaw(uint8_t *pat, uint16_t patlen)
{
    uint32_t hash = patlen * pat[0];
    if (patlen > 1)
        hash += pat[1];

    return (hash % INIT_HASH_SIZE);
}

static inline int B3gInitHashAdd(B3gCtx *ctx, B3gPattern *p)
{
    uint32_t hash = B3gInitHash(p);

    //printf("B3gInitHashAdd: %" PRIu32 "\n", hash);

    if (ctx->init_hash[hash] == NULL) {
        ctx->init_hash[hash] = p;
        //printf("B3gInitHashAdd: hash %" PRIu32 ", head %p\n", hash, ctx->init_hash[hash]);
        return 0;
    }

    B3gPattern *tt = NULL;
    B3gPattern *t = ctx->init_hash[hash];

    /* get the list tail */
    do {
        tt = t;
        t = t->next;
    } while (t != NULL);

    tt->next = p;
    //printf("B3gInitHashAdd: hash %" PRIu32 ", head %p\n", hash, ctx->init_hash[hash]);

    return 0;
}

static inline int B3gCmpPattern(B3gPattern *p, uint8_t *pat, uint16_t patlen, char flags);

static inline B3gPattern *B3gInitHashLookup(B3gCtx *ctx, uint8_t *pat, uint16_t patlen, char flags)
{
    uint32_t hash = B3gInitHashRaw(pat,patlen);

    //printf("B3gInitHashLookup: %" PRIu32 ", head %p\n", hash, ctx->init_hash[hash]);

    if (ctx->init_hash[hash] == NULL) {
        return NULL;
    }

    B3gPattern *t = ctx->init_hash[hash];
    for ( ; t != NULL; t = t->next) {
        if (B3gCmpPattern(t,pat,patlen,flags) == 1)
            return t;
    }

    return NULL;
}

static inline int B3gCmpPattern(B3gPattern *p, uint8_t *pat, uint16_t patlen, char flags)
{
    if (p->len != patlen)
        return 0;

    if (p->flags != flags)
        return 0;

    if (memcmp(p->cs, pat, patlen) != 0)
        return 0;

    return 1;
}

/*
 * INIT HASH END
 */

void B3gFreePattern(MpmCtx *mpm_ctx, B3gPattern *p)
{
    if (p && p->cs && p->cs != p->ci) {
        SCFree(p->cs);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= p->len;
    }

    if (p && p->ci) {
        SCFree(p->ci);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= p->len;
    }

    if (p && p->sids) {
        SCFree(p->sids);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= p->sids_size * sizeof(SigIntId);
    }

    if (p) {
        SCFree(p);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= sizeof(B3gPattern);
    }
}

/* B3gAddPattern
 *
 * pat: ptr to the pattern
 * patlen: length of the pattern
 * nocase: nocase flag: 1 enabled, 0 disable
 * pid: pattern id
 * sid: signature id (internal id)
 */
static int B3gAddPattern(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen, uint16_t offset, uint16_t depth, uint32_t pid, uint32_t sid, uint8_t flags)
{
    B3gCtx *ctx = (B3gCtx *)mpm_ctx->ctx;

    if (patlen == 0)
        return 0;

    /* get a memory piece */
    B3gPattern *p = B3gInitHashLookup(ctx, pat, patlen, flags);
    if (p == NULL) {
        p = B3gAllocPattern(mpm_ctx);
        if (p == NULL)
            goto error;

        p->len = patlen;
        p->flags = flags;
        p->id = pid;

        /* setup the case insensitive part of the pattern */
        p->ci = SCMalloc(patlen);
        if (p->ci == NULL)
            goto error;

        mpm_ctx->memory_cnt++;
        mpm_ctx->memory_size += patlen;
        memcpy_tolower(p->ci, pat, patlen);

        /* setup the case sensitive part of the pattern */
        if (p->flags & MPM_PATTERN_FLAG_NOCASE) {
            /* nocase means no difference between cs and ci */
            p->cs = p->ci;
        } else {
            if (memcmp(p->ci,pat,p->len) == 0) {
                /* no diff between cs and ci: pat is lowercase */
                p->cs = p->ci;
            } else {
                p->cs = SCMalloc(patlen);
                if (p->cs == NULL)
                    goto error;

                mpm_ctx->memory_cnt++;
                mpm_ctx->memory_size += patlen;
                memcpy(p->cs, pat, patlen);
            }
        }

        //printf("B3gAddPattern: ci \""); prt(p->ci,p->len);
        //printf("\" cs \""); prt(p->cs,p->len);
        //printf("\" prefix_ci %" PRIu32 ", prefix_cs %" PRIu32 "\n", p->prefix_ci, p->prefix_cs);

        p->sids_size = 1;
        p->sids = SCMalloc(p->sids_size * sizeof(SigIntId));
        BUG_ON(p->sids == NULL);
        p->sids[0] = sid;
        mpm_ctx->memory_cnt++;
        mpm_ctx->memory_size += sizeof(SigIntId);

        /* put in the pattern hash */
        B3gInitHashAdd(ctx, p);

        if (mpm_ctx->pattern_cnt == 65535) {
            printf("Max search words reached\n");
            exit(1);
        }
        mpm_ctx->pattern_cnt++;

        if (mpm_ctx->maxlen < patlen) mpm_ctx->maxlen = patlen;
        if (mpm_ctx->minlen == 0) mpm_ctx->minlen = patlen;
        else if (mpm_ctx->minlen > patlen) mpm_ctx->minlen = patlen;
    } else {
        /* Multiple sids for the same pid, so keep an array of sids. */

        /* TODO figure out how we can be called multiple times for the
         * same CTX with the same sid */
        int found = 0;
        uint32_t x = 0;
        for (x = 0; x < p->sids_size; x++) {
            if (p->sids[x] == sid) {
                found = 1;
                break;
            }
        }
        if (!found) {
            SigIntId *sids = SCRealloc(p->sids, (sizeof(SigIntId) * (p->sids_size + 1)));
            BUG_ON(sids == NULL);
            p->sids = sids;
            p->sids[p->sids_size] = sid;
            p->sids_size++;
            mpm_ctx->memory_size += sizeof(SigIntId);
        }
    }

    return 0;

error:
    B3gFreePattern(mpm_ctx, p);
    return -1;
}

int B3gAddPatternCI(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
    uint16_t offset, uint16_t depth, uint32_t pid, SigIntId sid, uint8_t flags)
{
    flags |= MPM_PATTERN_FLAG_NOCASE;
    return B3gAddPattern(mpm_ctx, pat, patlen, offset, depth, pid, sid, flags);
}

int B3gAddPatternCS(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
    uint16_t offset, uint16_t depth, uint32_t pid, SigIntId sid, uint8_t flags)
{
    return B3gAddPattern(mpm_ctx, pat, patlen, offset, depth, pid, sid, flags);
}

static uint32_t B3gBloomHash(void *data, uint16_t datalen, uint8_t iter, uint32_t hash_size)
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

static void B3gPrepareHash(MpmCtx *mpm_ctx)
{
    B3gCtx *ctx = (B3gCtx *)mpm_ctx->ctx;
    uint16_t i;
    uint16_t idx = 0;
    uint8_t idx8 = 0;

    ctx->hash = (B3gHashItem **)SCMalloc(sizeof(B3gHashItem *) * ctx->hash_size);
    if (ctx->hash == NULL)
        goto error;
    memset(ctx->hash, 0, sizeof(B3gHashItem *) * ctx->hash_size);

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += (sizeof(B3gHashItem *) * ctx->hash_size);

    /* 2 byte pattern hash */
    ctx->hash2 = (B3gHashItem **)SCMalloc(sizeof(B3gHashItem *) * ctx->hash_size);
    if (ctx->hash2 == NULL)
        goto error;
    memset(ctx->hash2, 0, sizeof(B3gHashItem *) * ctx->hash_size);

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += (sizeof(B3gHashItem *) * ctx->hash_size);

    /* alloc the pminlen array */
    ctx->pminlen = (uint8_t *)SCMalloc(sizeof(uint8_t) * ctx->hash_size);
    if (ctx->pminlen == NULL)
        goto error;
    memset(ctx->pminlen, 0, sizeof(uint8_t) * ctx->hash_size);

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += (sizeof(uint8_t) * ctx->hash_size);

    for (i = 0; i < mpm_ctx->pattern_cnt; i++)
    {
        if(ctx->parray[i]->len == 1) {
            idx8 = (uint8_t)ctx->parray[i]->ci[0];
            if (ctx->hash1[idx8].flags == 0) {
                ctx->hash1[idx8].idx = i;
                ctx->hash1[idx8].flags |= 0x01;
            } else {
                B3gHashItem *hi = B3gAllocHashItem(mpm_ctx);
                if (hi == NULL)
                    goto error;
                hi->idx = i;
                hi->flags |= 0x01;

                /* Append this HashItem to the list */
                B3gHashItem *thi = &ctx->hash1[idx8];
                while (thi->nxt) thi = thi->nxt;
                thi->nxt = hi;
            }
            ctx->pat_1_cnt++;
        } else if(ctx->parray[i]->len == 2) {
            idx = (uint16_t)(ctx->parray[i]->ci[0] << b3g_hash_shift | ctx->parray[i]->ci[1]);
            if (ctx->hash2[idx] == NULL) {
                B3gHashItem *hi = B3gAllocHashItem(mpm_ctx);
                if (hi == NULL)
                    goto error;
                hi->idx = i;
                hi->flags |= 0x01;

                ctx->hash2[idx] = hi;
            } else {
                B3gHashItem *hi = B3gAllocHashItem(mpm_ctx);
                if (hi == NULL)
                    goto error;
                hi->idx = i;
                hi->flags |= 0x01;

                /* Append this HashItem to the list */
                B3gHashItem *thi = ctx->hash2[idx];
                while (thi->nxt) thi = thi->nxt;
                thi->nxt = hi;
            }
            ctx->pat_2_cnt++;
        } else {
            idx = B3G_HASH(ctx->parray[i]->ci[ctx->m - 3], ctx->parray[i]->ci[ctx->m - 2], ctx->parray[i]->ci[ctx->m - 1]);
            //printf("idx %" PRIu32 ", %c.%c.%c\n", idx, ctx->parray[i]->ci[ctx->m - 3], ctx->parray[i]->ci[ctx->m - 2], ctx->parray[i]->ci[ctx->m - 1]);

            if (ctx->hash[idx] == NULL) {
                B3gHashItem *hi = B3gAllocHashItem(mpm_ctx);
                if (hi == NULL)
                    goto error;
                hi->idx = i;
                hi->flags |= 0x01;
                ctx->pminlen[idx] = ctx->parray[i]->len;

                ctx->hash[idx] = hi;
            } else {
                B3gHashItem *hi = B3gAllocHashItem(mpm_ctx);
                if (hi == NULL)
                    goto error;
                hi->idx = i;
                hi->flags |= 0x01;

                if (ctx->parray[i]->len < ctx->pminlen[idx])
                    ctx->pminlen[idx] = ctx->parray[i]->len;

                /* Append this HashItem to the list */
                B3gHashItem *thi = ctx->hash[idx];
                while (thi->nxt) thi = thi->nxt;
                thi->nxt = hi;
            }
            ctx->pat_x_cnt++;
        }
    }

    /* alloc the bloom array */
    ctx->bloom = (BloomFilter **)SCMalloc(sizeof(BloomFilter *) * ctx->hash_size);
    if (ctx->bloom == NULL)
        goto error;
    memset(ctx->bloom, 0, sizeof(BloomFilter *) * ctx->hash_size);

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += (sizeof(BloomFilter *) * ctx->hash_size);

    uint32_t h;
    for (h = 0; h < ctx->hash_size; h++) {
        B3gHashItem *hi = ctx->hash[h];
        if (hi == NULL)
            continue;

        ctx->bloom[h] = BloomFilterInit(b3g_bloom_size, 2, B3gBloomHash);
        if (ctx->bloom[h] == NULL)
            continue;

        mpm_ctx->memory_cnt += BloomFilterMemoryCnt(ctx->bloom[h]);
        mpm_ctx->memory_size += BloomFilterMemorySize(ctx->bloom[h]);

        if (ctx->pminlen[h] > 8)
            ctx->pminlen[h] = 8;

        B3gHashItem *thi = hi;
        do {
            BloomFilterAdd(ctx->bloom[h], ctx->parray[thi->idx]->ci, ctx->pminlen[h]);
            thi = thi->nxt;
        } while (thi != NULL);
    }

    return;
error:
    return;
}

int B3gBuildMatchArray(MpmCtx *mpm_ctx)
{
    B3gCtx *ctx = (B3gCtx *)mpm_ctx->ctx;

    ctx->B3G = SCMalloc(sizeof(B3G_TYPE) * ctx->hash_size);
    if (ctx->B3G == NULL)
        return -1;

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += (sizeof(B3G_TYPE) * ctx->hash_size);

    memset(ctx->B3G,0, b3g_hash_size * sizeof(B3G_TYPE));

    uint32_t j;
    uint32_t a;

    /* fill the match array */
    for (j = 0; j <= (ctx->m - B3G_Q); j++) {
        for (a = 0; a < mpm_ctx->pattern_cnt; a++) {
            if (ctx->parray[a]->len < ctx->m)
                continue;

            uint16_t h = B3G_HASH(u8_tolower(ctx->parray[a]->ci[j]),u8_tolower(ctx->parray[a]->ci[j+1]), u8_tolower(ctx->parray[a]->ci[j+2]));
//printf("B3gBuildMatchArray: h %" PRIu32 ", %c.%c.%c\n", h, u8_tolower(ctx->parray[a]->ci[j]),u8_tolower(ctx->parray[a]->ci[j+1]), u8_tolower(ctx->parray[a]->ci[j+2]));
            ctx->B3G[h] = ctx->B3G[h] | (1 << (ctx->m - j));
        }
    }

    ctx->s0 = 1;
    return 0;
}

int B3gPreparePatterns(MpmCtx *mpm_ctx)
{
    B3gCtx *ctx = (B3gCtx *)mpm_ctx->ctx;

    /* alloc the pattern array */
    ctx->parray = (B3gPattern **)SCMalloc(mpm_ctx->pattern_cnt * sizeof(B3gPattern *));
    if (ctx->parray == NULL)
        goto error;
    memset(ctx->parray, 0, mpm_ctx->pattern_cnt * sizeof(B3gPattern *));
    //printf("mpm_ctx %p, parray %p\n", mpm_ctx,ctx->parray);
    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += (mpm_ctx->pattern_cnt * sizeof(B3gPattern *));

    /* populate it with the patterns in the hash */
    uint32_t i = 0, p = 0;
    for (i = 0; i < INIT_HASH_SIZE; i++) {
        B3gPattern *node = ctx->init_hash[i], *nnode = NULL;
        for ( ; node != NULL; ) {
            nnode = node->next;
            node->next = NULL;

            ctx->parray[p] = node;

            p++;
            node = nnode;
        }
    }
    /* we no longer need the hash, so free it's memory */
    SCFree(ctx->init_hash);
    ctx->init_hash = NULL;

    /* set 'm' to the smallest pattern size */
    ctx->m = mpm_ctx->minlen;

    /* make sure 'm' stays in bounds
       m can be max WORD_SIZE - 1 */
    if (ctx->m >= B3G_WORD_SIZE) {
        ctx->m = B3G_WORD_SIZE - 1;
    }
    if (ctx->m < 3) ctx->m = 3;


    ctx->hash_size = b3g_hash_size;
    B3gPrepareHash(mpm_ctx);
    B3gBuildMatchArray(mpm_ctx);

    if (ctx->pat_1_cnt) {
        ctx->Search = B3gSearch1;
        if (ctx->pat_2_cnt) {
            ctx->Search = B3gSearch12;
            ctx->MBSearch = b3g_func;
        }
        ctx->MBSearch = b3g_func;
    } else if (ctx->pat_2_cnt) {
        ctx->Search = B3gSearch2;
        ctx->MBSearch = b3g_func;
    }


    return 0;
error:
    return -1;
}

void B3gPrintSearchStats(MpmThreadCtx *mpm_thread_ctx)
{
#ifdef B3G_COUNTERS
    B3gThreadCtx *tctx = (B3gThreadCtx *)mpm_thread_ctx->ctx;

    printf("B3g Thread Search stats (tctx %p)\n", tctx);
    printf("Total calls: %" PRIu32 "\n", tctx->stat_calls);
    printf("Avg m/search: %0.2f\n", tctx->stat_calls ? (float)((float)tctx->stat_m_total / (float)tctx->stat_calls) : 0);
    printf("D != 0 (possible match): %" PRIu32 "\n", tctx->stat_d0);
    printf("Avg hash items per bucket %0.2f (%" PRIu32 ")\n", tctx->stat_d0 ? (float)((float)tctx->stat_d0_hashloop / (float)tctx->stat_d0) : 0, tctx->stat_d0_hashloop);
    printf("Loop match: %" PRIu32 "\n", tctx->stat_loop_match);
    printf("Loop no match: %" PRIu32 "\n", tctx->stat_loop_no_match);
    printf("Num shifts: %" PRIu32 "\n", tctx->stat_num_shift);
    printf("Total shifts: %" PRIu32 "\n", tctx->stat_total_shift);
    printf("Avg shifts: %0.2f\n", tctx->stat_num_shift ? (float)((float)tctx->stat_total_shift / (float)tctx->stat_num_shift) : 0);
    printf("Total BloomFilter checks: %" PRIu32 "\n", tctx->stat_bloom_calls);
    printf("BloomFilter hits: %0.4f%% (%" PRIu32 ")\n", tctx->stat_bloom_calls ? (float)((float)((float)tctx->stat_bloom_hits / (float)tctx->stat_bloom_calls)*(float)100) : 0, tctx->stat_bloom_hits);
    printf("Avg pminlen: %0.2f\n\n", tctx->stat_pminlen_calls ? (float)((float)tctx->stat_pminlen_total / (float)tctx->stat_pminlen_calls) : 0);
#endif /* B3G_COUNTERS */
}

static inline int
memcmp_lowercase(uint8_t *s1, uint8_t *s2, uint16_t n)
{
    size_t i;

    /* check backwards because we already tested the first
     * 2 to 4 chars. This way we are more likely to detect
     * a miss and thus speed up a little... */
    for (i = n - 1; i; i--) {
        if (u8_tolower(*(s2+i)) != s1[i])
            return 1;
    }

    return 0;
}

/**
 * \brief   Function to get the user defined values for b3g algorithm from the
 *          config file 'suricata.yaml'
 */
void B3gGetConfig()
{
    ConfNode *b3g_conf;
    const char *hash_val = NULL;
    const char *bloom_val = NULL;
    const char *algo = NULL;

    /* init defaults */
    b3g_hash_size = HASHSIZE_LOW;
    b3g_bloom_size = BLOOMSIZE_MEDIUM;
    b3g_func = B3G_SEARCHFUNC;

    ConfNode *pm = ConfGetNode("pattern-matcher");

    if (pm != NULL) {

        TAILQ_FOREACH(b3g_conf, &pm->head, next) {
            if (strncmp(b3g_conf->val, "b3g", 3) == 0) {
                algo = ConfNodeLookupChildValue(b3g_conf->head.tqh_first,
                                                     "algo");
                hash_val = ConfNodeLookupChildValue(b3g_conf->head.tqh_first,
                                                    "hash_size");
                bloom_val = ConfNodeLookupChildValue(b3g_conf->head.tqh_first,
                                                     "bf_size");

                if (algo != NULL) {
                    if (strcmp(algo, "B3gSearch") == 0) {
                        b3g_func = B3gSearch;
                    } else if (strcmp(algo, "B3gSearchBNDMq") == 0) {
                        b3g_func = B3gSearchBNDMq;
                    }
                }

                if (hash_val != NULL) {
                    b3g_hash_size = MpmGetHashSize(hash_val);
                    switch (b3g_hash_size) {
                        case HASHSIZE_LOWEST:
                            b3g_hash_shift = B3G_HASHSHIFT_LOWEST;
                            b3g_hash_shift2 = B3G_HASHSHIFT_LOWEST2;
                            break;
                        case HASHSIZE_LOW:
                            b3g_hash_shift = B3G_HASHSHIFT_LOW;
                            b3g_hash_shift2 = B3G_HASHSHIFT_LOW2;
                            break;
                        case HASHSIZE_MEDIUM:
                            b3g_hash_shift = B3G_HASHSHIFT_MEDIUM;
                            b3g_hash_shift2 = B3G_HASHSHIFT_MEDIUM2;
                            break;
                        case HASHSIZE_HIGH:
                            b3g_hash_shift = B3G_HASHSHIFT_HIGH;
                            b3g_hash_shift2 = B3G_HASHSHIFT_HIGH2;
                            break;
                        case HASHSIZE_HIGHER:
                            b3g_hash_shift = B3G_HASHSHIFT_HIGHER;
                            b3g_hash_shift2 = B3G_HASHSHIFT_HIGHER2;
                            break;
                        case HASHSIZE_MAX:
                            b3g_hash_shift = B3G_HASHSHIFT_MAX;
                            b3g_hash_shift2 = B3G_HASHSHIFT_MAX2;
                            break;
                    }
                }

                if (bloom_val != NULL)
                    b3g_bloom_size = MpmGetBloomSize(bloom_val);

                SCLogDebug("hash size is %"PRIu32" and bloom size is %"PRIu32"",
                    b3g_hash_size, b3g_bloom_size);
            }
        }
    }
}

void B3gInitCtx (MpmCtx *mpm_ctx)
{
    //printf("B3gInitCtx: mpm_ctx %p\n", mpm_ctx);

    mpm_ctx->ctx = SCMalloc(sizeof(B3gCtx));
    if (mpm_ctx->ctx == NULL)
        return;

    memset(mpm_ctx->ctx, 0, sizeof(B3gCtx));

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += sizeof(B3gCtx);

    /* initialize the hash we use to speed up pattern insertions */
    B3gCtx *ctx = (B3gCtx *)mpm_ctx->ctx;
    ctx->init_hash = SCMalloc(sizeof(B3gPattern *) * INIT_HASH_SIZE);
    if (ctx->init_hash == NULL)
        return;

    memset(ctx->init_hash, 0, sizeof(B3gPattern *) * INIT_HASH_SIZE);

    /* Initialize the defaults value from the config file. The given check make
       sure that we query config file only once for config values */
    if (b3g_hash_size == 0)
        B3gGetConfig();

    /* init default */
    ctx->Search = b3g_func;
}

void B3gDestroyCtx(MpmCtx *mpm_ctx)
{
    B3gCtx *ctx = (B3gCtx *)mpm_ctx->ctx;
    if (ctx == NULL)
        return;

    if (ctx->init_hash) {
        SCFree(ctx->init_hash);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (INIT_HASH_SIZE * sizeof(B3gPattern *));
    }

    if (ctx->parray) {
        uint32_t i;
        for (i = 0; i < mpm_ctx->pattern_cnt; i++) {
            if (ctx->parray[i] != NULL) {
                B3gFreePattern(mpm_ctx, ctx->parray[i]);
            }
        }

        SCFree(ctx->parray);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (mpm_ctx->pattern_cnt * sizeof(B3gPattern));
    }

    if (ctx->B3G) {
        SCFree(ctx->B3G);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (sizeof(B3G_TYPE) * ctx->hash_size);
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

    if (ctx->hash) {
        uint32_t h;
        for (h = 0; h < ctx->hash_size; h++) {
            if (ctx->hash[h] == NULL)
                continue;

            B3gHashFree(mpm_ctx, ctx->hash[h]);
        }

        SCFree(ctx->hash);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (sizeof(B3gHashItem) * ctx->hash_size);
    }
    if (ctx->hash2) {
        uint32_t h;
        for (h = 0; h < ctx->hash_size; h++) {
            if (ctx->hash2[h] == NULL)
                continue;

            B3gHashFree(mpm_ctx, ctx->hash2[h]);
        }

        SCFree(ctx->hash2);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (sizeof(B3gHashItem) * ctx->hash_size);
    }

    if (ctx->pminlen) {
        SCFree(ctx->pminlen);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (sizeof(uint8_t) * ctx->hash_size);
    }

    SCFree(mpm_ctx->ctx);
    mpm_ctx->memory_cnt--;
    mpm_ctx->memory_size -= sizeof(B3gCtx);
}

void B3gThreadInitCtx(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx, uint32_t matchsize)
{
    memset(mpm_thread_ctx, 0, sizeof(MpmThreadCtx));

    if (sizeof(B3gThreadCtx) > 0) { /* size can be 0 when optimized */
        mpm_thread_ctx->ctx = SCMalloc(sizeof(B3gThreadCtx));
        if (mpm_thread_ctx->ctx == NULL)
            return;

        memset(mpm_thread_ctx->ctx, 0, sizeof(B3gThreadCtx));

        mpm_thread_ctx->memory_cnt++;
        mpm_thread_ctx->memory_size += sizeof(B3gThreadCtx);
    }
}

void B3gThreadDestroyCtx(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx)
{
    B3gThreadCtx *ctx = (B3gThreadCtx *)mpm_thread_ctx->ctx;

    B3gPrintSearchStats(mpm_thread_ctx);

    if (ctx != NULL) { /* can be NULL when optimized */
        mpm_thread_ctx->memory_cnt--;
        mpm_thread_ctx->memory_size -= sizeof(B3gThreadCtx);
        SCFree(mpm_thread_ctx->ctx);
    }
}

inline uint32_t B3gSearchWrap(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx, PatternMatcherQueue *pmq, uint8_t *buf, uint16_t buflen)
{
    B3gCtx *ctx = (B3gCtx *)mpm_ctx->ctx;
    return ctx->Search(mpm_ctx, mpm_thread_ctx, pmq, buf, buflen);
}

uint32_t B3gSearchBNDMq(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx, PatternMatcherQueue *pmq, uint8_t *buf, uint16_t buflen)
{
    B3gCtx *ctx = (B3gCtx *)mpm_ctx->ctx;
#ifdef B3G_COUNTERS
    B3gThreadCtx *tctx = (B3gThreadCtx *)mpm_thread_ctx->ctx;
#endif
    uint32_t pos = ctx->m - B3G_Q + 1, matches = 0;
    B3G_TYPE d;

    COUNT(tctx->stat_calls++);
    COUNT(tctx->stat_m_total+=ctx->m);

    if (buflen < ctx->m)
        return 0;

    uint8_t *bitarray = NULL;
    if (pmq) {
        bitarray = alloca(pmq->pattern_id_bitarray_size);
        memset(bitarray, 0, pmq->pattern_id_bitarray_size);
    }

    while (pos <= (uint32_t)(buflen - B3G_Q + 1)) {
        uint16_t h = B3G_HASH(u8_tolower(buf[pos - 1]), u8_tolower(buf[pos]),u8_tolower(buf[pos + 1]));
        d = ctx->B3G[h];

        if (d != 0) {
            COUNT(tctx->stat_d0++);
            uint32_t j = pos;
            uint32_t first = pos - (ctx->m - B3G_Q + 1);

            do {
                j = j - 1;
                if (d >= (uint32_t)(1 << (ctx->m - 1))) {
                    if (j > first) pos = j;
                    else {
                        /* get our patterns from the hash */
                        h = B3G_HASH(u8_tolower(buf[j + ctx->m - 3]), u8_tolower(buf[j + ctx->m - 2]),u8_tolower(buf[j + ctx->m - 1]));

                        if (ctx->bloom[h] != NULL) {
                            COUNT(tctx->stat_pminlen_calls++);
                            COUNT(tctx->stat_pminlen_total+=ctx->pminlen[h]);

                            if ((buflen - j) < ctx->pminlen[h]) {
                                goto skip_loop;
                            } else {
                                COUNT(tctx->stat_bloom_calls++);

                                if (BloomFilterTest(ctx->bloom[h], buf+j, ctx->pminlen[h]) == 0) {
                                    COUNT(tctx->stat_bloom_hits++);

                                    //printf("Bloom: %p, buflen %" PRIu32 ", pos %" PRIu32 ", p_min_len %" PRIu32 "\n", ctx->bloom[h], buflen, pos, ctx->pminlen[h]);
                                    goto skip_loop;
                                }
                            }
                        }

                        B3gHashItem *hi = ctx->hash[h], *thi;
                        for (thi = hi; thi != NULL; thi = thi->nxt) {
                            COUNT(tctx->stat_d0_hashloop++);
                            B3gPattern *p = ctx->parray[thi->idx];

                            if (p->flags & MPM_PATTERN_FLAG_NOCASE) {
                                if (buflen - j < p->len)
                                    continue;

                                if (memcmp_lowercase(p->ci, buf+j, p->len) == 0) {
                                    COUNT(tctx->stat_loop_match++);

                                    matches += MpmVerifyMatch(mpm_thread_ctx, pmq, p->id, bitarray, p->sids, p->sids_size);
                                } else {
                                    COUNT(tctx->stat_loop_no_match++);
                                }
                            } else {
                                if (buflen - j < p->len)
                                    continue;

                                if (memcmp(p->cs, buf+j, p->len) == 0) {
                                    COUNT(tctx->stat_loop_match++);

                                    matches += MpmVerifyMatch(mpm_thread_ctx, pmq, p->id, bitarray, p->sids, p->sids_size);
                                } else {
                                    COUNT(tctx->stat_loop_no_match++);
                                }
                            }
                        }
skip_loop:
                        //printf("output at pos %" PRIu32 ": ", j); prt(buf + (j), ctx->m); printf("\n");
                        ; // gcc doesn't like the goto label without this :-S
                    }
                }

                if (j == 0)
                    break;

                h = B3G_HASH(u8_tolower(buf[j - 1]), u8_tolower(buf[j - 0]),u8_tolower(buf[j+1]));
                d = (d << 1) & ctx->B3G[h];
            } while (d != 0);
        }
        COUNT(tctx->stat_num_shift++);
        COUNT(tctx->stat_total_shift += (ctx->m - B3G_Q + 1));
        pos = pos + ctx->m - B3G_Q + 1;
    }
    return matches;
}

uint32_t B3gSearch(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx, PatternMatcherQueue *pmq, uint8_t *buf, uint16_t buflen)
{
    B3gCtx *ctx = (B3gCtx *)mpm_ctx->ctx;
#ifdef B3G_COUNTERS
    B3gThreadCtx *tctx = (B3gThreadCtx *)mpm_thread_ctx->ctx;
#endif
    uint32_t pos = 0, matches = 0;
    B3G_TYPE d;
    uint32_t j;

    COUNT(tctx->stat_calls++);
    COUNT(tctx->stat_m_total+=ctx->m);

    if (buflen < ctx->m)
        return 0;

    uint8_t *bitarray = NULL;
    if (pmq) {
        bitarray = alloca(pmq->pattern_id_bitarray_size);
        memset(bitarray, 0, pmq->pattern_id_bitarray_size);
    }

    while (pos <= (buflen - ctx->m)) {
        j = ctx->m - 2;
        d = ~0;

        do {
            uint16_t h = B3G_HASH(u8_tolower(buf[pos + j - 1]), u8_tolower(buf[pos + j - 0]),u8_tolower(buf[pos + j + 1]));
            d = ((d << 1) & ctx->B3G[h]);
            j = j - 1;
        } while (d != 0 && j != 0);

        /* (partial) match, move on to verification */
        if (d != 0) {
            COUNT(tctx->stat_d0++);
            //printf("output at pos %" PRIu32 ": ", pos); prt(buf + pos, ctx->m); printf("\n");

            /* get our patterns from the hash */
            uint16_t h = B3G_HASH(u8_tolower(buf[pos + ctx->m - 3]), u8_tolower(buf[pos + ctx->m - 2]),u8_tolower(buf[pos + ctx->m - 1]));

            if (ctx->bloom[h] != NULL) {
                COUNT(tctx->stat_pminlen_calls++);
                COUNT(tctx->stat_pminlen_total+=ctx->pminlen[h]);

                if ((buflen - pos) < ctx->pminlen[h]) {
                    goto skip_loop;
                } else {
                    COUNT(tctx->stat_bloom_calls++);

                    if (BloomFilterTest(ctx->bloom[h], buf+pos, ctx->pminlen[h]) == 0) {
                        COUNT(tctx->stat_bloom_hits++);

                        //printf("Bloom: %p, buflen %" PRIu32 ", pos %" PRIu32 ", p_min_len %" PRIu32 "\n", ctx->bloom[h], buflen, pos, ctx->pminlen[h]);
                        goto skip_loop;
                    }
                }
            }

            B3gHashItem *hi = ctx->hash[h], *thi;
            for (thi = hi; thi != NULL; thi = thi->nxt) {
                COUNT(tctx->stat_d0_hashloop++);
                B3gPattern *p = ctx->parray[thi->idx];

                if (p->flags & MPM_PATTERN_FLAG_NOCASE) {
                    if (buflen - pos < p->len)
                        continue;

                    if (memcmp_lowercase(p->ci, buf+pos, p->len) == 0) {
                        COUNT(tctx->stat_loop_match++);

                        matches += MpmVerifyMatch(mpm_thread_ctx, pmq, p->id, bitarray, p->sids, p->sids_size);
                    } else {
                        COUNT(tctx->stat_loop_no_match++);
                    }
                } else {
                    if (buflen - pos < p->len)
                        continue;

                    if (memcmp(p->cs, buf+pos, p->len) == 0) {
                        COUNT(tctx->stat_loop_match++);

                        matches += MpmVerifyMatch(mpm_thread_ctx, pmq, p->id, bitarray, p->sids, p->sids_size);
                    } else {
                        COUNT(tctx->stat_loop_no_match++);
                    }
                }
            }
skip_loop:
            pos = pos + 1;
            //pos = pos + ctx->s0;
        } else {
            COUNT(tctx->stat_num_shift++);
            COUNT(tctx->stat_total_shift += (j + 1));

            pos = pos + j + 1;
        }
    }

    //printf("Total matches %" PRIu32 "\n", matches);
    return matches;
}

uint32_t B3gSearch12(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx, PatternMatcherQueue *pmq, uint8_t *buf, uint16_t buflen)
{
    B3gCtx *ctx = (B3gCtx *)mpm_ctx->ctx;
    uint8_t *bufmin = buf;
    uint8_t *bufend = buf + buflen - 1;
    uint32_t cnt = 0;
    B3gPattern *p;
    B3gHashItem *thi, *hi;

    //printf("BUF "); prt(buf,buflen); printf("\n");

    uint8_t *bitarray = NULL;
    if (pmq) {
        bitarray = alloca(pmq->pattern_id_bitarray_size);
        memset(bitarray, 0, pmq->pattern_id_bitarray_size);
    }

    while (buf <= bufend) {
        uint8_t h8 = u8_tolower(*buf);
        hi = &ctx->hash1[h8];

        if (hi->flags & 0x01) {
            for (thi = hi; thi != NULL; thi = thi->nxt) {
                p = ctx->parray[thi->idx];

                if (p->flags & MPM_PATTERN_FLAG_NOCASE) {
                    if (h8 == p->ci[0]) {
                        cnt += MpmVerifyMatch(mpm_thread_ctx, pmq, p->id, bitarray, p->sids, p->sids_size);
                    }
                } else {
                    if (*buf == p->cs[0]) {
                        cnt += MpmVerifyMatch(mpm_thread_ctx, pmq, p->id, bitarray, p->sids, p->sids_size);
                    }
                }
            }
        }

        if (buf != bufend) {
            /* save one conversion by reusing h8 */
            uint16_t h16 = (uint16_t)(h8 << b3g_hash_shift | u8_tolower(*(buf+1)));
            hi = ctx->hash2[h16];

            for (thi = hi; thi != NULL; thi = thi->nxt) {
                p = ctx->parray[thi->idx];

                if (p->flags & MPM_PATTERN_FLAG_NOCASE) {
                    if (h8 == p->ci[0] && u8_tolower(*(buf+1)) == p->ci[1]) {
                        cnt += MpmVerifyMatch(mpm_thread_ctx, pmq, p->id, bitarray, p->sids, p->sids_size);
                    }
                } else {
                    if (*buf == p->cs[0] && *(buf+1) == p->cs[1]) {
                        cnt += MpmVerifyMatch(mpm_thread_ctx, pmq, p->id, bitarray, p->sids, p->sids_size);
                    }
                }
            }
        }
        buf += 1;
    }

    //printf("B3gSearch12: after 1/2byte cnt %" PRIu32 "\n", cnt);
    if (ctx->pat_x_cnt > 0) {
        /* Pass bufmin on because buf no longer points to the
         * start of the buffer. */
        cnt += ctx->MBSearch(mpm_ctx, mpm_thread_ctx, pmq, bufmin, buflen);
        //printf("B3gSearch1: after 2+byte cnt %" PRIu32 "\n", cnt);
    }
    return cnt;
}

uint32_t B3gSearch2(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx, PatternMatcherQueue *pmq, uint8_t *buf, uint16_t buflen)
{
    B3gCtx *ctx = (B3gCtx *)mpm_ctx->ctx;
    uint8_t *bufmin = buf;
    uint8_t *bufend = buf + buflen - 1;
    uint32_t cnt = 0;
    B3gPattern *p;
    B3gHashItem *thi, *hi;

    if (buflen < 2)
        return 0;

    //printf("BUF "); prt(buf,buflen); printf("\n");

    uint8_t *bitarray = NULL;
    if (pmq) {
        bitarray = alloca(pmq->pattern_id_bitarray_size);
        memset(bitarray, 0, pmq->pattern_id_bitarray_size);
    }

    while (buf <= bufend) {
        uint16_t h = u8_tolower(*buf) << b3g_hash_shift | u8_tolower(*(buf+1));
        hi = ctx->hash2[h];

        if (hi != NULL) {
            for (thi = hi; thi != NULL; thi = thi->nxt) {
                p = ctx->parray[thi->idx];

                if (p->len != 2)
                    continue;

                if (p->flags & MPM_PATTERN_FLAG_NOCASE) {
                    if (u8_tolower(*buf) == p->ci[0] && u8_tolower(*(buf+1)) == p->ci[1]) {
                        //printf("CI Exact match: "); prt(p->ci, p->len); printf(" in buf "); prt(buf, p->len);printf(" (B3gSearch1)\n");
                        if (MpmVerifyMatch(mpm_thread_ctx, pmq, p->id, bitarray, p->sids, p->sids_size))
                            cnt++;
                    }
                } else {
                    if (*buf == p->cs[0] && *(buf+1) == p->cs[1]) {
                        //printf("CS Exact match: "); prt(p->cs, p->len); printf(" in buf "); prt(buf, p->len);printf(" (B3gSearch1)\n");
                        if (MpmVerifyMatch(mpm_thread_ctx, pmq, p->id, bitarray, p->sids, p->sids_size))
                            cnt++;
                    }
                }
            }
        }
        buf += 1;
    }

    //printf("B3gSearch2: after 2byte cnt %" PRIu32 "\n", cnt);
    if (ctx->pat_x_cnt) {
        /* Pass bufmin on because buf no longer points to the
         * start of the buffer. */
        cnt += ctx->MBSearch(mpm_ctx, mpm_thread_ctx, pmq, bufmin, buflen);
        //printf("B3gSearch1: after 2+byte cnt %" PRIu32 "\n", cnt);
    }
    return cnt;
}
uint32_t B3gSearch1(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx, PatternMatcherQueue *pmq, uint8_t *buf, uint16_t buflen)
{
    B3gCtx *ctx = (B3gCtx *)mpm_ctx->ctx;
    uint8_t *bufmin = buf;
    uint8_t *bufend = buf + buflen - 1;
    uint32_t cnt = 0;
    B3gPattern *p;
    B3gHashItem *thi, *hi;

    if (buflen == 0)
        return 0;

    //printf("BUF "); prt(buf,buflen); printf("\n");

    uint8_t *bitarray = NULL;
    if (pmq) {
        bitarray = alloca(pmq->pattern_id_bitarray_size);
        memset(bitarray, 0, pmq->pattern_id_bitarray_size);
    }

    while (buf <= bufend) {
        uint8_t h = u8_tolower(*buf);
        hi = &ctx->hash1[h];

        if (hi->flags & 0x01) {
            for (thi = hi; thi != NULL; thi = thi->nxt) {
                p = ctx->parray[thi->idx];

                if (p->len != 1)
                    continue;

                if (p->flags & MPM_PATTERN_FLAG_NOCASE) {
                    if (u8_tolower(*buf) == p->ci[0]) {
                        cnt += MpmVerifyMatch(mpm_thread_ctx, pmq, p->id, bitarray, p->sids, p->sids_size);
                    }
                } else {
                    if (*buf == p->cs[0]) {
                        cnt += MpmVerifyMatch(mpm_thread_ctx, pmq, p->id, bitarray, p->sids, p->sids_size);
                    }
                }
            }
        }
        buf += 1;
    }

    if (ctx->pat_2_cnt) {
        /* Pass bufmin on because buf no longer points to the
         * start of the buffer. */
        cnt += ctx->MBSearch2(mpm_ctx, mpm_thread_ctx, pmq, bufmin, buflen);
    } else if (ctx->pat_x_cnt) {
        cnt += ctx->MBSearch(mpm_ctx, mpm_thread_ctx, pmq, bufmin, buflen);
    }
    return cnt;
}

void MpmB3gRegister (void)
{
    mpm_table[MPM_B3G].name = "b3g";
    mpm_table[MPM_B3G].max_pattern_length = B3G_WORD_SIZE;
    mpm_table[MPM_B3G].InitCtx = B3gInitCtx;
    mpm_table[MPM_B3G].InitThreadCtx = B3gThreadInitCtx;
    mpm_table[MPM_B3G].DestroyCtx = B3gDestroyCtx;
    mpm_table[MPM_B3G].DestroyThreadCtx = B3gThreadDestroyCtx;
    mpm_table[MPM_B3G].AddPattern = B3gAddPatternCS;
    mpm_table[MPM_B3G].AddPatternNocase = B3gAddPatternCI;
    mpm_table[MPM_B3G].Prepare = B3gPreparePatterns;
    mpm_table[MPM_B3G].Search = B3gSearchWrap;
    mpm_table[MPM_B3G].Cleanup = NULL;
    mpm_table[MPM_B3G].PrintCtx = B3gPrintInfo;
    mpm_table[MPM_B3G].PrintThreadCtx = B3gPrintSearchStats;
    mpm_table[MPM_B3G].RegisterUnittests = B3gRegisterTests;
}

/*
 * TESTS
 */

#ifdef UNITTESTS
static int B3gTestInit01 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmInitCtx(&mpm_ctx, MPM_B3G);
    B3gCtx *ctx = (B3gCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0); /* 1 match */

    B3gPreparePatterns(&mpm_ctx);

    if (ctx->m == 4)
        result = 1;
    else
        printf("4 != %" PRIu32 " ", ctx->m);

    B3gDestroyCtx(&mpm_ctx);
    return result;
}

#if 0
static int B3gTestS0Init01 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmInitCtx(&mpm_ctx, MPM_B3G);
    B3gCtx *ctx = (B3gCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0); /* 1 match */

    B3gPreparePatterns(&mpm_ctx);

    if (ctx->s0 == 4)
        result = 1;
    else
        printf("4 != %" PRIu32 " ", ctx->s0);

    B3gDestroyCtx(&mpm_ctx);
    return result;
}

static int B3gTestS0Init02 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmInitCtx(&mpm_ctx, MPM_B3G);
    B3gCtx *ctx = (B3gCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0); /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"cdef", 4, 0, 0, 1, 0); /* 1 match */

    B3gPreparePatterns(&mpm_ctx);

    if (ctx->s0 == 2)
        result = 1;
    else
        printf("2 != %" PRIu32 " ", ctx->s0);

    B3gDestroyCtx(&mpm_ctx);
    return result;
}

static int B3gTestS0Init03 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmInitCtx(&mpm_ctx, MPM_B3G);
    B3gCtx *ctx = (B3gCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0); /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"bcde", 4, 0, 0, 1, 0); /* 1 match */

    B3gPreparePatterns(&mpm_ctx);

    if (ctx->s0 == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ", ctx->s0);

    B3gDestroyCtx(&mpm_ctx);
    return result;
}

static int B3gTestS0Init04 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmInitCtx(&mpm_ctx, MPM_B3G);
    B3gCtx *ctx = (B3gCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abab", 4, 0, 0, 0, 0); /* 1 match */

    B3gPreparePatterns(&mpm_ctx);

    if (ctx->s0 == 2)
        result = 1;
    else
        printf("2 != %" PRIu32 " ", ctx->s0);

    B3gDestroyCtx(&mpm_ctx);
    return result;
}

static int B3gTestS0Init05 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmInitCtx(&mpm_ctx, MPM_B3G);
    B3gCtx *ctx = (B3gCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcab", 5, 0, 0, 0, 0); /* 1 match */

    B3gPreparePatterns(&mpm_ctx);

    if (ctx->s0 == 3)
        result = 1;
    else
        printf("3 != %" PRIu32 " ", ctx->s0);

    B3gDestroyCtx(&mpm_ctx);
    return result;
}
#endif

static int B3gTestSearch01 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B3G);
    B3gCtx *ctx = (B3gCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0); /* 1 match */

    B3gPreparePatterns(&mpm_ctx);
    B3gThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"abcdefghjiklmnopqrstuvwxyz", 26);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B3gThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B3gDestroyCtx(&mpm_ctx);
    return result;
}

static int B3gTestSearch02 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B3G);
    B3gCtx *ctx = (B3gCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abce", 4, 0, 0, 0, 0, 0); /* 1 match */

    B3gPreparePatterns(&mpm_ctx);
    B3gThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"abcdefghjiklmnopqrstuvwxyz", 26);

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ",cnt);

    B3gThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B3gDestroyCtx(&mpm_ctx);
    return result;
}

static int B3gTestSearch03 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B3G);
    B3gCtx *ctx = (B3gCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0); /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"bcde", 4, 0, 0, 1, 0, 0); /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"fghj", 4, 0, 0, 2, 0, 0); /* 1 match */

    B3gPreparePatterns(&mpm_ctx);
    B3gThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 3 /* 3 patterns */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"abcdefghjiklmnopqrstuvwxyz", 26);

    if (cnt == 3)
        result = 1;
    else
        printf("3 != %" PRIu32 " ",cnt);

    B3gThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B3gDestroyCtx(&mpm_ctx);
    return result;
}

/* test patterns longer than 'm'. M is 4 here. */
static int B3gTestSearch04 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B3G);
    B3gCtx *ctx = (B3gCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0); /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"bcdegh", 6, 0, 0, 1, 0, 0); /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"fghjxyz", 7, 0, 0, 2, 0, 0); /* 1 match */

    B3gPreparePatterns(&mpm_ctx);
    B3gThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 3 /* 3 patterns */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"abcdefghjiklmnopqrstuvwxyz", 26);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B3gThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B3gDestroyCtx(&mpm_ctx);
    return result;
}

/* case insensitive test patterns longer than 'm'. M is 4 here. */
static int B3gTestSearch05 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B3G);
    B3gCtx *ctx = (B3gCtx *)mpm_ctx.ctx;

    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"ABCD", 4, 0, 0, 0, 0, 0); /* 1 match */
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"bCdEfG", 6, 0, 0, 1, 0, 0); /* 1 match */
    MpmAddPatternCI(&mpm_ctx, (uint8_t *)"fghJikl", 7, 0, 0, 2, 0, 0); /* 1 match */

    B3gPreparePatterns(&mpm_ctx);
    B3gThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 3 /* 3 patterns */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"abcdefghjiklmnopqrstuvwxyz", 26);

    if (cnt == 3)
        result = 1;
    else
        printf("3 != %" PRIu32 " ",cnt);

    B3gThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B3gDestroyCtx(&mpm_ctx);
    return result;
}

static int B3gTestSearch06 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B3G);
    B3gCtx *ctx = (B3gCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0); /* 1 match */

    B3gPreparePatterns(&mpm_ctx);
    B3gThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"abcd", 4);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B3gThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B3gDestroyCtx(&mpm_ctx);
    return result;
}

static int B3gTestSearch07 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B3G);
    B3gCtx *ctx = (B3gCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"A", 1, 0, 0, 0, 0, 0); /* should match 30 times */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AA", 2, 0, 0, 1, 0, 0); /* should match 29 times */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AAA", 3, 0, 0, 2, 0, 0); /* should match 28 times */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AAAAA", 5, 0, 0, 3, 0, 0); /* 26 */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AAAAAAAAAA", 10, 0, 0, 4, 0, 0); /* 21 */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 30, 0, 0, 5, 0, 0); /* 1 */
    /* total matches: 135 */

    B3gPreparePatterns(&mpm_ctx);
    B3gThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 6 /* 6 patterns */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 30);

    if (cnt == 135)
        result = 1;
    else
        printf("135 != %" PRIu32 " ",cnt);

    B3gThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B3gDestroyCtx(&mpm_ctx);
    return result;
}

static int B3gTestSearch08 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B3G);
    B3gCtx *ctx = (B3gCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0); /* 1 match */

    B3gPreparePatterns(&mpm_ctx);
    B3gThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"a", 1);

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ",cnt);

    B3gThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B3gDestroyCtx(&mpm_ctx);
    return result;
}

static int B3gTestSearch09 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B3G);
    B3gCtx *ctx = (B3gCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"ab", 2, 0, 0, 0, 0, 0); /* 1 match */

    B3gPreparePatterns(&mpm_ctx);
    B3gThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"ab", 2);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B3gThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B3gDestroyCtx(&mpm_ctx);
    return result;
}

static int B3gTestSearch10 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B3G);
    B3gCtx *ctx = (B3gCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcdefgh", 8, 0, 0, 0, 0, 0); /* 1 match */

    B3gPreparePatterns(&mpm_ctx);
    B3gThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    char *input = "012345679012345679012345679012345679012345679012345679"
                  "012345679012345679012345679012345679abcdefgh0123456790"
                  "123456790123456790123456790123456790123456790123456790"
                  "12345679012345679012345679";

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)input, strlen(input));

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B3gThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B3gDestroyCtx(&mpm_ctx);
    return result;
}

static int B3gTestSearch11 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B3G);
    B3gCtx *ctx = (B3gCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0); /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"abcde", 5, 0, 0, 0, 0, 0); /* 1 match */

    B3gPreparePatterns(&mpm_ctx);
    B3gThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 2 /* 2 patterns */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"abcdefghjiklmnopqrstuvwxyz", 26);

    if (cnt == 2)
        result = 1;
    else
        printf("2 != %" PRIu32 " ",cnt);

    B3gThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B3gDestroyCtx(&mpm_ctx);
    return result;
}

static int B3gTestSearch12 (void)
{
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B3G);
    B3gCtx *ctx = (B3gCtx *)mpm_ctx.ctx;

    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"wxyz", 4, 0, 0, 0, 0, 0); /* 1 match */
    MpmAddPatternCS(&mpm_ctx, (uint8_t *)"vwxyz", 5, 0, 0, 0, 0, 0); /* 1 match */

    B3gPreparePatterns(&mpm_ctx);
    B3gThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 2 /* 2 patterns */);

    uint32_t cnt = ctx->Search(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"abcdefghjiklmnopqrstuvwxyz", 26);

    if (cnt == 2)
        result = 1;
    else
        printf("2 != %" PRIu32 " ",cnt);

    B3gThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B3gDestroyCtx(&mpm_ctx);
    return result;
}

#endif /* UNITTESTS */

void B3gRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("B3gTestInit01", B3gTestInit01, 1);
/*
    UtRegisterTest("B3gTestS0Init01", B3gTestS0Init01, 1);
    UtRegisterTest("B3gTestS0Init02", B3gTestS0Init02, 1);
    UtRegisterTest("B3gTestS0Init03", B3gTestS0Init03, 1);
    UtRegisterTest("B3gTestS0Init04", B3gTestS0Init04, 1);
    UtRegisterTest("B3gTestS0Init05", B3gTestS0Init05, 1);
*/
    UtRegisterTest("B3gTestSearch01", B3gTestSearch01, 1);

    UtRegisterTest("B3gTestSearch02", B3gTestSearch02, 1);
    UtRegisterTest("B3gTestSearch03", B3gTestSearch03, 1);
    UtRegisterTest("B3gTestSearch04", B3gTestSearch04, 1);
    UtRegisterTest("B3gTestSearch05", B3gTestSearch05, 1);
    UtRegisterTest("B3gTestSearch06", B3gTestSearch06, 1);
    UtRegisterTest("B3gTestSearch07", B3gTestSearch07, 1);
    UtRegisterTest("B3gTestSearch08", B3gTestSearch08, 1);
    UtRegisterTest("B3gTestSearch09", B3gTestSearch09, 1);
    UtRegisterTest("B3gTestSearch10", B3gTestSearch10, 1);
    UtRegisterTest("B3gTestSearch11", B3gTestSearch11, 1);
    UtRegisterTest("B3gTestSearch12", B3gTestSearch12, 1);
#endif /* UNITTESTS */
}


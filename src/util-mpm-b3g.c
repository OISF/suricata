/* 3 gram implementation of the (S)BNDMq pattern matching algorithm.
 *
 * Copyright (c) 2009 Victor Julien <victor@inliniac.net>
 *
 * Ideas:
 *  - B3g does a full match in the scan phase of up to 'm' characters,
 *    in case of a case insensitive search we could say it's match if
 *    the pattern is of len 'm' or just compare the rest of the chars.
 *
 * TODO:
 *  - Try to get the S0 calculation right.
 *
 */

#include "suricata-common.h"
#include "suricata.h"
#include "util-bloomfilter.h"
#include "util-mpm-b3g.h"
#include "util-unittest.h"
#include "conf.h"
#include "util-debug.h"

#define INIT_HASH_SIZE 65536

#ifdef B3G_COUNTERS
#define COUNT(counter) \
        (counter)
#else
#define COUNT(counter)
#endif /* B3G_COUNTERS */

static uint32_t b3g_hash_size = 0;
static uint32_t b3g_bloom_size = 0;
static void *b3g_scan_func;

void B3gInitCtx (MpmCtx *, int);
void B3gThreadInitCtx(MpmCtx *, MpmThreadCtx *, uint32_t);
void B3gDestroyCtx(MpmCtx *);
void B3gThreadDestroyCtx(MpmCtx *, MpmThreadCtx *);
int B3gAddScanPatternCI(MpmCtx *, uint8_t *, uint16_t, uint16_t, uint16_t, uint32_t, uint32_t, uint8_t);
int B3gAddScanPatternCS(MpmCtx *, uint8_t *, uint16_t, uint16_t, uint16_t, uint32_t, uint32_t, uint8_t);
int B3gPreparePatterns(MpmCtx *);
inline uint32_t B3gScanWrap(MpmCtx *, MpmThreadCtx *, PatternMatcherQueue *, uint8_t *, uint16_t);
uint32_t B3gScan1(MpmCtx *, MpmThreadCtx *, PatternMatcherQueue *, uint8_t *, uint16_t);
uint32_t B3gScan2(MpmCtx *, MpmThreadCtx *, PatternMatcherQueue *, uint8_t *, uint16_t);
uint32_t B3gScan12(MpmCtx *, MpmThreadCtx *, PatternMatcherQueue *, uint8_t *, uint16_t);
uint32_t B3gScan(MpmCtx *, MpmThreadCtx *, PatternMatcherQueue *, uint8_t *, uint16_t);
uint32_t B3gScanBNDMq(MpmCtx *, MpmThreadCtx *, PatternMatcherQueue *, uint8_t *, uint16_t);
void B3gPrintInfo(MpmCtx *);
void B3gPrintSearchStats(MpmThreadCtx *);
void B3gRegisterTests(void);

void MpmB3gRegister (void) {
    mpm_table[MPM_B3G].name = "b3g";
    mpm_table[MPM_B3G].max_pattern_length = B3G_WORD_SIZE;
    mpm_table[MPM_B3G].InitCtx = B3gInitCtx;
    mpm_table[MPM_B3G].InitThreadCtx = B3gThreadInitCtx;
    mpm_table[MPM_B3G].DestroyCtx = B3gDestroyCtx;
    mpm_table[MPM_B3G].DestroyThreadCtx = B3gThreadDestroyCtx;
    mpm_table[MPM_B3G].AddScanPattern = B3gAddScanPatternCS;
    mpm_table[MPM_B3G].AddScanPatternNocase = B3gAddScanPatternCI;
    //mpm_table[MPM_B3G].AddPattern = B3gAddPatternCS;
    //mpm_table[MPM_B3G].AddPatternNocase = B3gAddPatternCI;
    mpm_table[MPM_B3G].Prepare = B3gPreparePatterns;
    mpm_table[MPM_B3G].Scan = B3gScanWrap;
    //mpm_table[MPM_B3G].Search = B3gSearchWrap;
    //mpm_table[MPM_B3G].Cleanup = MpmMatchCleanup;
    mpm_table[MPM_B3G].PrintCtx = B3gPrintInfo;
    mpm_table[MPM_B3G].PrintThreadCtx = B3gPrintSearchStats;
    mpm_table[MPM_B3G].RegisterUnittests = B3gRegisterTests;
}

/* append an endmatch to a pattern
 *
 * Only used in the initialization phase */
static inline void B3gEndMatchAppend(MpmCtx *mpm_ctx, B3gPattern *p,
    uint16_t offset, uint16_t depth, uint32_t pid, uint32_t sid,
    uint8_t nosearch)
{
    MpmEndMatch *em = MpmAllocEndMatch(mpm_ctx);
    if (em == NULL) {
        printf("ERROR: B3gAllocEndMatch failed\n");
        return;
    }

    em->id = pid;
    em->sig_id = sid;
    em->depth = depth;
    em->offset = offset;

    if (nosearch)
        em->flags |= MPM_ENDMATCH_NOSEARCH;

    if (p->em == NULL) {
        p->em = em;
        return;
    }

    MpmEndMatch *m = p->em;
    while (m->next) {
        m = m->next;
    }
    m->next = em;
}

/** \todo XXX Unused??? */
#if 0
static void prt (uint8_t *buf, uint16_t buflen) {
    uint16_t i;

    for (i = 0; i < buflen; i++) {
        if (isprint(buf[i])) printf("%c", buf[i]);
        else                 printf("\\x%" PRIX32, buf[i]);
    }
    //printf("\n");
}
#endif

void B3gPrintInfo(MpmCtx *mpm_ctx) {
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
    printf("Scan Patterns:   %" PRIu32 "\n", mpm_ctx->scan_pattern_cnt);
    printf("Total Patterns:  %" PRIu32 "\n", mpm_ctx->total_pattern_cnt);
    printf("Smallest:        %" PRIu32 "\n", mpm_ctx->scan_minlen);
    printf("Largest:         %" PRIu32 "\n", mpm_ctx->scan_maxlen);
    printf("Hash size:       %" PRIu32 "\n", ctx->scan_hash_size);
    printf("\n");
}

static inline B3gPattern *B3gAllocPattern(MpmCtx *mpm_ctx) {
    B3gPattern *p = SCMalloc(sizeof(B3gPattern));
    if (p == NULL) {
        printf("ERROR: B3gAllocPattern: SCMalloc failed\n");
        exit(EXIT_FAILURE);
    }
    memset(p,0,sizeof(B3gPattern));

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += sizeof(B3gPattern);
    return p;
}

static inline B3gHashItem *
B3gAllocHashItem(MpmCtx *mpm_ctx) {
    B3gHashItem *hi = SCMalloc(sizeof(B3gHashItem));
    if (hi == NULL) {
        printf("ERROR: B3gAllocHashItem: SCMalloc failed\n");
        exit(EXIT_FAILURE);
    }
    memset(hi,0,sizeof(B3gHashItem));

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += sizeof(B3gHashItem);
    return hi;
}

static void B3gHashFree(MpmCtx *mpm_ctx, B3gHashItem *hi) {
    if (hi == NULL)
        return;

    B3gHashItem *t = hi->nxt;
    B3gHashFree(mpm_ctx, t);

    mpm_ctx->memory_cnt--;
    mpm_ctx->memory_size -= sizeof(B3gHashItem);
    SCFree(hi);
}

static inline void memcpy_tolower(uint8_t *d, uint8_t *s, uint16_t len) {
    uint16_t i;
    for (i = 0; i < len; i++) {
        d[i] = u8_tolower(s[i]);
    }
}

/*
 * INIT HASH START
 */
static inline uint32_t B3gInitHash(B3gPattern *p) {
    uint32_t hash = p->len * p->cs[0];
    if (p->len > 1)
        hash += p->cs[1];

    return (hash % INIT_HASH_SIZE);
}

static inline uint32_t B3gInitHashRaw(uint8_t *pat, uint16_t patlen) {
    uint32_t hash = patlen * pat[0];
    if (patlen > 1)
        hash += pat[1];

    return (hash % INIT_HASH_SIZE);
}

static inline int B3gInitHashAdd(B3gCtx *ctx, B3gPattern *p) {
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

static inline int B3gCmpPattern(B3gPattern *p, uint8_t *pat, uint16_t patlen, char nocase);

static inline B3gPattern *B3gInitHashLookup(B3gCtx *ctx, uint8_t *pat, uint16_t patlen, char nocase) {
    uint32_t hash = B3gInitHashRaw(pat,patlen);

    //printf("B3gInitHashLookup: %" PRIu32 ", head %p\n", hash, ctx->init_hash[hash]);

    if (ctx->init_hash[hash] == NULL) {
        return NULL;
    }

    B3gPattern *t = ctx->init_hash[hash];
    for ( ; t != NULL; t = t->next) {
        if (B3gCmpPattern(t,pat,patlen,nocase) == 1)
            return t;
    }

    return NULL;
}

static inline int B3gCmpPattern(B3gPattern *p, uint8_t *pat, uint16_t patlen, char nocase) {
    if (p->len != patlen)
        return 0;

    if (!((nocase && p->flags & B3G_NOCASE) || (!nocase && !(p->flags & B3G_NOCASE))))
        return 0;

    if (memcmp(p->cs, pat, patlen) != 0)
        return 0;

    return 1;
}

/*
 * INIT HASH END
 */

void B3gFreePattern(MpmCtx *mpm_ctx, B3gPattern *p) {
    if (p && p->em) {
        MpmEndMatchFreeAll(mpm_ctx, p->em);
    }

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
static inline int B3gAddPattern(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen, uint16_t offset, uint16_t depth, char nocase, char scan, uint32_t pid, uint32_t sid, uint8_t nosearch) {
    B3gCtx *ctx = (B3gCtx *)mpm_ctx->ctx;

//    printf("B3gAddPattern: ctx %p \"", mpm_ctx); prt(pat, patlen);
//    printf("\" id %" PRIu32 ", nocase %s\n", id, nocase ? "true" : "false");

    if (patlen == 0)
        return 0;

    /* get a memory piece */
    B3gPattern *p = B3gInitHashLookup(ctx, pat, patlen, nocase);
    if (p == NULL) {
//        printf("B3gAddPattern: allocing new pattern\n");
        p = B3gAllocPattern(mpm_ctx);
        if (p == NULL)
            goto error;

        p->len = patlen;

        if (nocase) p->flags |= B3G_NOCASE;

        /* setup the case insensitive part of the pattern */
        p->ci = SCMalloc(patlen);
        if (p->ci == NULL) goto error;
        mpm_ctx->memory_cnt++;
        mpm_ctx->memory_size += patlen;
        memcpy_tolower(p->ci, pat, patlen);

        /* setup the case sensitive part of the pattern */
        if (p->flags & B3G_NOCASE) {
            /* nocase means no difference between cs and ci */
            p->cs = p->ci;
        } else {
            if (memcmp(p->ci,pat,p->len) == 0) {
                /* no diff between cs and ci: pat is lowercase */
                p->cs = p->ci;
            } else {
                p->cs = SCMalloc(patlen);
                if (p->cs == NULL) goto error;
                mpm_ctx->memory_cnt++;
                mpm_ctx->memory_size += patlen;
                memcpy(p->cs, pat, patlen);
            }
        }

        //printf("B3gAddPattern: ci \""); prt(p->ci,p->len);
        //printf("\" cs \""); prt(p->cs,p->len);
        //printf("\" prefix_ci %" PRIu32 ", prefix_cs %" PRIu32 "\n", p->prefix_ci, p->prefix_cs);

        /* put in the pattern hash */
        B3gInitHashAdd(ctx, p);

        if (mpm_ctx->pattern_cnt == 65535) {
            printf("Max search words reached\n");
            exit(1);
        }
        if (scan) mpm_ctx->scan_pattern_cnt++;
        mpm_ctx->pattern_cnt++;

        if (mpm_ctx->scan_maxlen < patlen) mpm_ctx->scan_maxlen = patlen;
        if (mpm_ctx->scan_minlen == 0) mpm_ctx->scan_minlen = patlen;
        else if (mpm_ctx->scan_minlen > patlen) mpm_ctx->scan_minlen = patlen;
    } else {
        /* if we're reusing a pattern, check we need to check that it is a
         * scan pattern if that is what we're adding. If so we set the pattern
         * to be a scan pattern. */
        if (mpm_ctx->scan_maxlen < patlen) mpm_ctx->scan_maxlen = patlen;
        if (mpm_ctx->scan_minlen == 0) mpm_ctx->scan_minlen = patlen;
        else if (mpm_ctx->scan_minlen > patlen) mpm_ctx->scan_minlen = patlen;
    }

    /* we need a match */
    B3gEndMatchAppend(mpm_ctx, p, offset, depth, pid, sid, nosearch);

    mpm_ctx->total_pattern_cnt++;
    return 0;

error:
    B3gFreePattern(mpm_ctx, p);
    return -1;
}

int B3gAddScanPatternCI(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
    uint16_t offset, uint16_t depth, uint32_t pid, uint32_t sid, uint8_t nosearch)
{
    return B3gAddPattern(mpm_ctx, pat, patlen, offset, depth, /* nocase */1, /* scan */1, pid, sid, nosearch);
}

int B3gAddScanPatternCS(MpmCtx *mpm_ctx, uint8_t *pat, uint16_t patlen,
    uint16_t offset, uint16_t depth, uint32_t pid, uint32_t sid, uint8_t nosearch)
{
    return B3gAddPattern(mpm_ctx, pat, patlen, offset, depth, /* nocase */0, /* scan */1, pid, sid, nosearch);
}

static uint32_t B3gBloomHash(void *data, uint16_t datalen, uint8_t iter, uint32_t hash_size) {
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

static void B3gPrepareScanHash(MpmCtx *mpm_ctx) {
    B3gCtx *ctx = (B3gCtx *)mpm_ctx->ctx;
    uint16_t i;
    uint16_t idx = 0;
    uint8_t idx8 = 0;

    ctx->scan_hash = (B3gHashItem **)SCMalloc(sizeof(B3gHashItem *) * ctx->scan_hash_size);
    if (ctx->scan_hash == NULL) goto error;
    memset(ctx->scan_hash, 0, sizeof(B3gHashItem *) * ctx->scan_hash_size);

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += (sizeof(B3gHashItem *) * ctx->scan_hash_size);

    /* 2 byte pattern hash */
    ctx->scan_hash2 = (B3gHashItem **)SCMalloc(sizeof(B3gHashItem *) * ctx->scan_hash_size);
    if (ctx->scan_hash2 == NULL) goto error;
    memset(ctx->scan_hash2, 0, sizeof(B3gHashItem *) * ctx->scan_hash_size);

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += (sizeof(B3gHashItem *) * ctx->scan_hash_size);

    /* alloc the pminlen array */
    ctx->scan_pminlen = (uint8_t *)SCMalloc(sizeof(uint8_t) * ctx->scan_hash_size);
    if (ctx->scan_pminlen == NULL) goto error;
    memset(ctx->scan_pminlen, 0, sizeof(uint8_t) * ctx->scan_hash_size);

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += (sizeof(uint8_t) * ctx->scan_hash_size);

    for (i = 0; i < mpm_ctx->pattern_cnt; i++)
    {
        if(ctx->parray[i]->len == 1) {
            idx8 = (uint8_t)ctx->parray[i]->ci[0];
            if (ctx->scan_hash1[idx8].flags == 0) {
                ctx->scan_hash1[idx8].idx = i;
                ctx->scan_hash1[idx8].flags |= 0x01;
            } else {
                B3gHashItem *hi = B3gAllocHashItem(mpm_ctx);
                hi->idx = i;
                hi->flags |= 0x01;

                /* Append this HashItem to the list */
                B3gHashItem *thi = &ctx->scan_hash1[idx8];
                while (thi->nxt) thi = thi->nxt;
                thi->nxt = hi;
            }
            ctx->scan_1_pat_cnt++;
        } else if(ctx->parray[i]->len == 2) {
            idx = (uint16_t)(ctx->parray[i]->ci[0] << B3G_HASHSHIFT | ctx->parray[i]->ci[1]);
            if (ctx->scan_hash2[idx] == NULL) {
                B3gHashItem *hi = B3gAllocHashItem(mpm_ctx);
                hi->idx = i;
                hi->flags |= 0x01;

                ctx->scan_hash2[idx] = hi;
            } else {
                B3gHashItem *hi = B3gAllocHashItem(mpm_ctx);
                hi->idx = i;
                hi->flags |= 0x01;

                /* Append this HashItem to the list */
                B3gHashItem *thi = ctx->scan_hash2[idx];
                while (thi->nxt) thi = thi->nxt;
                thi->nxt = hi;
            }
            ctx->scan_2_pat_cnt++;
        } else {
            idx = B3G_HASH(ctx->parray[i]->ci[ctx->scan_m - 3], ctx->parray[i]->ci[ctx->scan_m - 2], ctx->parray[i]->ci[ctx->scan_m - 1]);
            //printf("idx %" PRIu32 ", %c.%c.%c\n", idx, ctx->parray[i]->ci[ctx->scan_m - 3], ctx->parray[i]->ci[ctx->scan_m - 2], ctx->parray[i]->ci[ctx->scan_m - 1]);

            if (ctx->scan_hash[idx] == NULL) {
                B3gHashItem *hi = B3gAllocHashItem(mpm_ctx);
                hi->idx = i;
                hi->flags |= 0x01;
                ctx->scan_pminlen[idx] = ctx->parray[i]->len;

                ctx->scan_hash[idx] = hi;
            } else {
                B3gHashItem *hi = B3gAllocHashItem(mpm_ctx);
                hi->idx = i;
                hi->flags |= 0x01;

                if (ctx->parray[i]->len < ctx->scan_pminlen[idx])
                    ctx->scan_pminlen[idx] = ctx->parray[i]->len;

                /* Append this HashItem to the list */
                B3gHashItem *thi = ctx->scan_hash[idx];
                while (thi->nxt) thi = thi->nxt;
                thi->nxt = hi;
            }
            ctx->scan_x_pat_cnt++;
        }
    }

    /* alloc the bloom array */
    ctx->scan_bloom = (BloomFilter **)SCMalloc(sizeof(BloomFilter *) * ctx->scan_hash_size);
    if (ctx->scan_bloom == NULL) goto error;
    memset(ctx->scan_bloom, 0, sizeof(BloomFilter *) * ctx->scan_hash_size);

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += (sizeof(BloomFilter *) * ctx->scan_hash_size);

    uint32_t h;
    for (h = 0; h < ctx->scan_hash_size; h++) {
        B3gHashItem *hi = ctx->scan_hash[h];
        if (hi == NULL)
            continue;

        ctx->scan_bloom[h] = BloomFilterInit(b3g_bloom_size, 2, B3gBloomHash);
        if (ctx->scan_bloom[h] == NULL)
            continue;

        mpm_ctx->memory_cnt += BloomFilterMemoryCnt(ctx->scan_bloom[h]);
        mpm_ctx->memory_size += BloomFilterMemorySize(ctx->scan_bloom[h]);

        if (ctx->scan_pminlen[h] > 8)
            ctx->scan_pminlen[h] = 8;

        B3gHashItem *thi = hi;
        do {
            BloomFilterAdd(ctx->scan_bloom[h], ctx->parray[thi->idx]->ci, ctx->scan_pminlen[h]);
            thi = thi->nxt;
        } while (thi != NULL);
    }

    return;
error:
    return;
}

int B3gBuildScanMatchArray(MpmCtx *mpm_ctx) {
    B3gCtx *ctx = (B3gCtx *)mpm_ctx->ctx;

    ctx->scan_B3G = SCMalloc(sizeof(B3G_TYPE) * ctx->scan_hash_size);
    if (ctx->scan_B3G == NULL)
        return -1;

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += (sizeof(B3G_TYPE) * ctx->scan_hash_size);

    memset(ctx->scan_B3G,0, b3g_hash_size * sizeof(B3G_TYPE));

    uint32_t j;
    uint32_t a;

    /* fill the match array */
    for (j = 0; j <= (ctx->scan_m - B3G_Q); j++) {
        for (a = 0; a < mpm_ctx->pattern_cnt; a++) {
            if (ctx->parray[a]->len < ctx->scan_m)
                continue;

            uint16_t h = B3G_HASH(u8_tolower(ctx->parray[a]->ci[j]),u8_tolower(ctx->parray[a]->ci[j+1]), u8_tolower(ctx->parray[a]->ci[j+2]));
//printf("B3gBuildScanMatchArray: h %" PRIu32 ", %c.%c.%c\n", h, u8_tolower(ctx->parray[a]->ci[j]),u8_tolower(ctx->parray[a]->ci[j+1]), u8_tolower(ctx->parray[a]->ci[j+2]));
            ctx->scan_B3G[h] = ctx->scan_B3G[h] | (1 << (ctx->scan_m - j));
        }
    }

    ctx->scan_s0 = 1;
    return 0;
}

int B3gPreparePatterns(MpmCtx *mpm_ctx) {
    B3gCtx *ctx = (B3gCtx *)mpm_ctx->ctx;

    /* alloc the pattern array */
    ctx->parray = (B3gPattern **)SCMalloc(mpm_ctx->pattern_cnt * sizeof(B3gPattern *));
    if (ctx->parray == NULL) goto error;
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
    ctx->scan_m = mpm_ctx->scan_minlen;

    /* make sure 'm' stays in bounds
       m can be max WORD_SIZE - 1 */
    if (ctx->scan_m >= B3G_WORD_SIZE) {
        ctx->scan_m = B3G_WORD_SIZE - 1;
    }
    if (ctx->scan_m < 3) ctx->scan_m = 3;


    ctx->scan_hash_size = b3g_hash_size;
    B3gPrepareScanHash(mpm_ctx);
    B3gBuildScanMatchArray(mpm_ctx);

    if (ctx->scan_1_pat_cnt) {
        ctx->Scan = B3gScan1;
        if (ctx->scan_2_pat_cnt) {
            ctx->Scan = B3gScan12;
            ctx->MBScan = b3g_scan_func;
        }
        ctx->MBScan = b3g_scan_func;
    } else if (ctx->scan_2_pat_cnt) {
        ctx->Scan = B3gScan2;
        ctx->MBScan = b3g_scan_func;
    }


    return 0;
error:
    return -1;
}

void B3gPrintSearchStats(MpmThreadCtx *mpm_thread_ctx) {
#ifdef B3G_COUNTERS
    B3gThreadCtx *tctx = (B3gThreadCtx *)mpm_thread_ctx->ctx;

    printf("B3g Thread Search stats (tctx %p)\n", tctx);
    printf("Scan phase:\n");
    printf("Total calls/scans: %" PRIu32 "\n", tctx->scan_stat_calls);
    printf("Avg m/scan: %0.2f\n", tctx->scan_stat_calls ? (float)((float)tctx->scan_stat_m_total / (float)tctx->scan_stat_calls) : 0);
    printf("D != 0 (possible match): %" PRIu32 "\n", tctx->scan_stat_d0);
    printf("Avg hash items per bucket %0.2f (%" PRIu32 ")\n", tctx->scan_stat_d0 ? (float)((float)tctx->scan_stat_d0_hashloop / (float)tctx->scan_stat_d0) : 0, tctx->scan_stat_d0_hashloop);
    printf("Loop match: %" PRIu32 "\n", tctx->scan_stat_loop_match);
    printf("Loop no match: %" PRIu32 "\n", tctx->scan_stat_loop_no_match);
    printf("Num shifts: %" PRIu32 "\n", tctx->scan_stat_num_shift);
    printf("Total shifts: %" PRIu32 "\n", tctx->scan_stat_total_shift);
    printf("Avg shifts: %0.2f\n", tctx->scan_stat_num_shift ? (float)((float)tctx->scan_stat_total_shift / (float)tctx->scan_stat_num_shift) : 0);
    printf("Total BloomFilter checks: %" PRIu32 "\n", tctx->scan_stat_bloom_calls);
    printf("BloomFilter hits: %0.4f%% (%" PRIu32 ")\n", tctx->scan_stat_bloom_calls ? (float)((float)((float)tctx->scan_stat_bloom_hits / (float)tctx->scan_stat_bloom_calls)*(float)100) : 0, tctx->scan_stat_bloom_hits);
    printf("Avg pminlen: %0.2f\n\n", tctx->scan_stat_pminlen_calls ? (float)((float)tctx->scan_stat_pminlen_total / (float)tctx->scan_stat_pminlen_calls) : 0);
#endif /* B3G_COUNTERS */
}

static inline int
memcmp_lowercase(uint8_t *s1, uint8_t *s2, uint16_t n) {
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
    const char *scan_algo = NULL;

    /* init defaults */
    b3g_hash_size = HASHSIZE_LOW;
    b3g_bloom_size = BLOOMSIZE_MEDIUM;
    b3g_scan_func = B3G_SCANFUNC;

    ConfNode *pm = ConfGetNode("pattern-matcher");

    if (pm != NULL) {

        TAILQ_FOREACH(b3g_conf, &pm->head, next) {
            if (strncmp(b3g_conf->val, "b3g", 3) == 0) {
                scan_algo = ConfNodeLookupChildValue(b3g_conf->head.tqh_first,
                                                     "scan_algo");
                hash_val = ConfNodeLookupChildValue(b3g_conf->head.tqh_first,
                                                    "hash_size");
                bloom_val = ConfNodeLookupChildValue(b3g_conf->head.tqh_first,
                                                     "bf_size");

                if (scan_algo != NULL) {
                    if (strcmp(scan_algo, "B3gScan") == 0) {
                        b3g_scan_func = B3gScan;
                    } else if (strcmp(scan_algo, "B3gScanBNDMq") == 0) {
                        b3g_scan_func = B3gScanBNDMq;
                    }
                }

                if (hash_val != NULL)
                    b3g_hash_size = MpmGetHashSize(hash_val);

                if (bloom_val != NULL)
                    b3g_bloom_size = MpmGetBloomSize(bloom_val);

                SCLogDebug("hash size is %"PRIu32" and bloom size is %"PRIu32"",
                    b3g_hash_size, b3g_bloom_size);
            }
        }
    }
}

void B3gInitCtx (MpmCtx *mpm_ctx, int module_handle) {
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
    ctx->Scan = b3g_scan_func;
}

void B3gDestroyCtx(MpmCtx *mpm_ctx) {
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

    if (ctx->scan_B3G) {
        SCFree(ctx->scan_B3G);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (sizeof(B3G_TYPE) * ctx->scan_hash_size);
    }

    if (ctx->scan_bloom) {
        uint32_t h;
        for (h = 0; h < ctx->scan_hash_size; h++) {
            if (ctx->scan_bloom[h] == NULL)
                continue;

            mpm_ctx->memory_cnt -= BloomFilterMemoryCnt(ctx->scan_bloom[h]);
            mpm_ctx->memory_size -= BloomFilterMemorySize(ctx->scan_bloom[h]);

            BloomFilterFree(ctx->scan_bloom[h]);
        }

        SCFree(ctx->scan_bloom);

        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (sizeof(BloomFilter *) * ctx->scan_hash_size);
    }

    if (ctx->scan_hash) {
        uint32_t h;
        for (h = 0; h < ctx->scan_hash_size; h++) {
            if (ctx->scan_hash[h] == NULL)
                continue;

            B3gHashFree(mpm_ctx, ctx->scan_hash[h]);
        }

        SCFree(ctx->scan_hash);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (sizeof(B3gHashItem) * ctx->scan_hash_size);
    }
    if (ctx->scan_hash2) {
        uint32_t h;
        for (h = 0; h < ctx->scan_hash_size; h++) {
            if (ctx->scan_hash2[h] == NULL)
                continue;

            B3gHashFree(mpm_ctx, ctx->scan_hash2[h]);
        }

        SCFree(ctx->scan_hash2);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (sizeof(B3gHashItem) * ctx->scan_hash_size);
    }

    if (ctx->scan_pminlen) {
        SCFree(ctx->scan_pminlen);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= (sizeof(uint8_t) * ctx->scan_hash_size);
    }

    SCFree(mpm_ctx->ctx);
    mpm_ctx->memory_cnt--;
    mpm_ctx->memory_size -= sizeof(B3gCtx);
}

void B3gThreadInitCtx(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx, uint32_t matchsize) {
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

void B3gThreadDestroyCtx(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx) {
    B3gThreadCtx *ctx = (B3gThreadCtx *)mpm_thread_ctx->ctx;

    B3gPrintSearchStats(mpm_thread_ctx);

    if (ctx != NULL) { /* can be NULL when optimized */
        mpm_thread_ctx->memory_cnt--;
        mpm_thread_ctx->memory_size -= sizeof(B3gThreadCtx);
        SCFree(mpm_thread_ctx->ctx);
    }
}

inline uint32_t B3gScanWrap(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx, PatternMatcherQueue *pmq, uint8_t *buf, uint16_t buflen) {
    B3gCtx *ctx = (B3gCtx *)mpm_ctx->ctx;
    return ctx->Scan(mpm_ctx, mpm_thread_ctx, pmq, buf, buflen);
}

uint32_t B3gScanBNDMq(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx, PatternMatcherQueue *pmq, uint8_t *buf, uint16_t buflen) {
    B3gCtx *ctx = (B3gCtx *)mpm_ctx->ctx;
#ifdef B3G_COUNTERS
    B3gThreadCtx *tctx = (B3gThreadCtx *)mpm_thread_ctx->ctx;
#endif
    uint32_t pos = ctx->scan_m - B3G_Q + 1, matches = 0;
    B3G_TYPE d;

    COUNT(tctx->scan_stat_calls++);
    COUNT(tctx->scan_stat_m_total+=ctx->scan_m);

    if (buflen < ctx->scan_m)
        return 0;

    while (pos <= (uint32_t)(buflen - B3G_Q + 1)) {
        uint16_t h = B3G_HASH(u8_tolower(buf[pos - 1]), u8_tolower(buf[pos]),u8_tolower(buf[pos + 1]));
        d = ctx->scan_B3G[h];

        if (d != 0) {
            COUNT(tctx->scan_stat_d0++);
            uint32_t j = pos;
            uint32_t first = pos - (ctx->scan_m - B3G_Q + 1);

            do {
                j = j - 1;
                if (d >= (uint32_t)(1 << (ctx->scan_m - 1))) {
                    if (j > first) pos = j;
                    else {
                        /* get our patterns from the hash */
                        h = B3G_HASH(u8_tolower(buf[j + ctx->scan_m - 3]), u8_tolower(buf[j + ctx->scan_m - 2]),u8_tolower(buf[j + ctx->scan_m - 1]));

                        if (ctx->scan_bloom[h] != NULL) {
                            COUNT(tctx->scan_stat_pminlen_calls++);
                            COUNT(tctx->scan_stat_pminlen_total+=ctx->scan_pminlen[h]);

                            if ((buflen - j) < ctx->scan_pminlen[h]) {
                                goto skip_loop;
                            } else {
                                COUNT(tctx->scan_stat_bloom_calls++);

                                if (BloomFilterTest(ctx->scan_bloom[h], buf+j, ctx->scan_pminlen[h]) == 0) {
                                    COUNT(tctx->scan_stat_bloom_hits++);

                                    //printf("Bloom: %p, buflen %" PRIu32 ", pos %" PRIu32 ", p_min_len %" PRIu32 "\n", ctx->scan_bloom[h], buflen, pos, ctx->scan_pminlen[h]);
                                    goto skip_loop;
                                }
                            }
                        }

                        B3gHashItem *hi = ctx->scan_hash[h], *thi;
                        for (thi = hi; thi != NULL; thi = thi->nxt) {
                            COUNT(tctx->scan_stat_d0_hashloop++);
                            B3gPattern *p = ctx->parray[thi->idx];

                            if (p->flags & B3G_NOCASE) {
                                if (buflen - j < p->len)
                                    continue;

                                if (memcmp_lowercase(p->ci, buf+j, p->len) == 0) {
                                    COUNT(tctx->scan_stat_loop_match++);

                                    matches += MpmVerifyMatch(mpm_thread_ctx, pmq, p->em, j, p->len);
                                } else {
                                    COUNT(tctx->scan_stat_loop_no_match++);
                                }
                            } else {
                                if (buflen - j < p->len)
                                    continue;

                                if (memcmp(p->cs, buf+j, p->len) == 0) {
                                    COUNT(tctx->scan_stat_loop_match++);

                                    matches += MpmVerifyMatch(mpm_thread_ctx, pmq, p->em, j, p->len);
                                } else {
                                    COUNT(tctx->scan_stat_loop_no_match++);
                                }
                            }
                        }
skip_loop:
                        //printf("output at pos %" PRIu32 ": ", j); prt(buf + (j), ctx->scan_m); printf("\n");
                        ; // gcc doesn't like the goto label without this :-S
                    }
                }

                if (j == 0)
                    break;

                h = B3G_HASH(u8_tolower(buf[j - 1]), u8_tolower(buf[j - 0]),u8_tolower(buf[j+1]));
                d = (d << 1) & ctx->scan_B3G[h];
            } while (d != 0);
        }
        COUNT(tctx->scan_stat_num_shift++);
        COUNT(tctx->scan_stat_total_shift += (ctx->scan_m - B3G_Q + 1));
        pos = pos + ctx->scan_m - B3G_Q + 1;
    }
    return matches;
}

uint32_t B3gScan(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx, PatternMatcherQueue *pmq, uint8_t *buf, uint16_t buflen) {
    B3gCtx *ctx = (B3gCtx *)mpm_ctx->ctx;
#ifdef B3G_COUNTERS
    B3gThreadCtx *tctx = (B3gThreadCtx *)mpm_thread_ctx->ctx;
#endif
    uint32_t pos = 0, matches = 0;
    B3G_TYPE d;
    uint32_t j;

    COUNT(tctx->scan_stat_calls++);
    COUNT(tctx->scan_stat_m_total+=ctx->scan_m);

    if (buflen < ctx->scan_m)
        return 0;

    while (pos <= (buflen - ctx->scan_m)) {
        j = ctx->scan_m - 2;
        d = ~0;

        do {
            uint16_t h = B3G_HASH(u8_tolower(buf[pos + j - 1]), u8_tolower(buf[pos + j - 0]),u8_tolower(buf[pos + j + 1]));
//            printf("scan: h %" PRIu32 ", %c.%c.%c\n", h, u8_tolower(buf[pos + j - 1]), u8_tolower(buf[pos + j - 0]),u8_tolower(buf[pos + j + 1]));
            d = ((d << 1) & ctx->scan_B3G[h]);
            j = j - 1;
        } while (d != 0 && j != 0);
//        printf("scan: d %" PRIu32 ", j %" PRIu32 "\n", d, j);

        /* (partial) match, move on to verification */
        if (d != 0) {
            COUNT(tctx->scan_stat_d0++);
            //printf("output at pos %" PRIu32 ": ", pos); prt(buf + pos, ctx->scan_m); printf("\n");

            /* get our patterns from the hash */
            uint16_t h = B3G_HASH(u8_tolower(buf[pos + ctx->scan_m - 3]), u8_tolower(buf[pos + ctx->scan_m - 2]),u8_tolower(buf[pos + ctx->scan_m - 1]));

            if (ctx->scan_bloom[h] != NULL) {
                COUNT(tctx->scan_stat_pminlen_calls++);
                COUNT(tctx->scan_stat_pminlen_total+=ctx->scan_pminlen[h]);

                if ((buflen - pos) < ctx->scan_pminlen[h]) {
                    goto skip_loop;
                } else {
                    COUNT(tctx->scan_stat_bloom_calls++);

                    if (BloomFilterTest(ctx->scan_bloom[h], buf+pos, ctx->scan_pminlen[h]) == 0) {
                        COUNT(tctx->scan_stat_bloom_hits++);

                        //printf("Bloom: %p, buflen %" PRIu32 ", pos %" PRIu32 ", p_min_len %" PRIu32 "\n", ctx->scan_bloom[h], buflen, pos, ctx->scan_pminlen[h]);
                        goto skip_loop;
                    }
                }
            }

            B3gHashItem *hi = ctx->scan_hash[h], *thi;
            for (thi = hi; thi != NULL; thi = thi->nxt) {
                COUNT(tctx->scan_stat_d0_hashloop++);
                B3gPattern *p = ctx->parray[thi->idx];

                if (p->flags & B3G_NOCASE) {
                    if (buflen - pos < p->len)
                        continue;

                    if (memcmp_lowercase(p->ci, buf+pos, p->len) == 0) {
                        COUNT(tctx->scan_stat_loop_match++);

                        matches += MpmVerifyMatch(mpm_thread_ctx, pmq, p->em, pos, p->len);
                    } else {
                        COUNT(tctx->scan_stat_loop_no_match++);
                    }
                } else {
                    if (buflen - pos < p->len)
                        continue;

                    if (memcmp(p->cs, buf+pos, p->len) == 0) {
                        COUNT(tctx->scan_stat_loop_match++);

                        matches += MpmVerifyMatch(mpm_thread_ctx, pmq, p->em, pos, p->len);
                    } else {
                        COUNT(tctx->scan_stat_loop_no_match++);
                    }
                }
            }
skip_loop:
            pos = pos + 1;
            //pos = pos + ctx->scan_s0;
        } else {
            COUNT(tctx->scan_stat_num_shift++);
            COUNT(tctx->scan_stat_total_shift += (j + 1));

            pos = pos + j + 1;
        }
    }

    //printf("Total matches %" PRIu32 "\n", matches);
    return matches;
}

uint32_t B3gScan12(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx, PatternMatcherQueue *pmq, uint8_t *buf, uint16_t buflen) {
    B3gCtx *ctx = (B3gCtx *)mpm_ctx->ctx;
    uint8_t *bufmin = buf;
    uint8_t *bufend = buf + buflen - 1;
    uint32_t cnt = 0;
    B3gPattern *p;
    B3gHashItem *thi, *hi;

    //printf("BUF "); prt(buf,buflen); printf("\n");

    while (buf <= bufend) {
        uint8_t h8 = u8_tolower(*buf);
        hi = &ctx->scan_hash1[h8];

        if (hi->flags & 0x01) {
            for (thi = hi; thi != NULL; thi = thi->nxt) {
                p = ctx->parray[thi->idx];

                if (p->flags & B3G_NOCASE) {
                    if (h8 == p->ci[0]) {
                        cnt += MpmVerifyMatch(mpm_thread_ctx, pmq, p->em, (buf+1 - bufmin), p->len);
                    }
                } else {
                    if (*buf == p->cs[0]) {
                        cnt += MpmVerifyMatch(mpm_thread_ctx, pmq, p->em, (buf+1 - bufmin), p->len);
                    }
                }
            }
        }

        if (buf != bufend) {
            /* save one conversion by reusing h8 */
            uint16_t h16 = (uint16_t)(h8 << B3G_HASHSHIFT | u8_tolower(*(buf+1)));
            hi = ctx->scan_hash2[h16];

            for (thi = hi; thi != NULL; thi = thi->nxt) {
                p = ctx->parray[thi->idx];

                if (p->flags & B3G_NOCASE) {
                    if (h8 == p->ci[0] && u8_tolower(*(buf+1)) == p->ci[1]) {
                        cnt += MpmVerifyMatch(mpm_thread_ctx, pmq, p->em, (buf+1 - bufmin), p->len);
                    }
                } else {
                    if (*buf == p->cs[0] && *(buf+1) == p->cs[1]) {
                        cnt += MpmVerifyMatch(mpm_thread_ctx, pmq, p->em, (buf+1 - bufmin), p->len);
                    }
                }
            }
        }
        buf += 1;
    }

    //printf("B3gSearch12: after 1/2byte cnt %" PRIu32 "\n", cnt);
    if (ctx->scan_x_pat_cnt > 0) {
        /* Pass bufmin on because buf no longer points to the
         * start of the buffer. */
        cnt += ctx->MBScan(mpm_ctx, mpm_thread_ctx, pmq, bufmin, buflen);
        //printf("B3gSearch1: after 2+byte cnt %" PRIu32 "\n", cnt);
    }
    return cnt;
}

uint32_t B3gScan2(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx, PatternMatcherQueue *pmq, uint8_t *buf, uint16_t buflen) {
    B3gCtx *ctx = (B3gCtx *)mpm_ctx->ctx;
    uint8_t *bufmin = buf;
    uint8_t *bufend = buf + buflen - 1;
    uint32_t cnt = 0;
    B3gPattern *p;
    MpmEndMatch *em;
    B3gHashItem *thi, *hi;

    if (buflen < 2)
        return 0;

    //printf("BUF "); prt(buf,buflen); printf("\n");

    while (buf <= bufend) {
        uint16_t h = u8_tolower(*buf) << B3G_HASHSHIFT | u8_tolower(*(buf+1));
        hi = ctx->scan_hash2[h];

        if (hi != NULL) {
            for (thi = hi; thi != NULL; thi = thi->nxt) {
                p = ctx->parray[thi->idx];

                if (p->len != 2)
                    continue;

                if (p->flags & B3G_NOCASE) {
                    if (u8_tolower(*buf) == p->ci[0] && u8_tolower(*(buf+1)) == p->ci[1]) {
                        //printf("CI Exact match: "); prt(p->ci, p->len); printf(" in buf "); prt(buf, p->len);printf(" (B3gSearch1)\n");
                        for (em = p->em; em; em = em->next) {
                            if (MpmVerifyMatch(mpm_thread_ctx, pmq, em, (buf+1 - bufmin), p->len))
                                cnt++;
                        }
                    }
                } else {
                    if (*buf == p->cs[0] && *(buf+1) == p->cs[1]) {
                        //printf("CS Exact match: "); prt(p->cs, p->len); printf(" in buf "); prt(buf, p->len);printf(" (B3gSearch1)\n");
                        for (em = p->em; em; em = em->next) {
                            if (MpmVerifyMatch(mpm_thread_ctx, pmq, em, (buf+1 - bufmin), p->len))
                                cnt++;
                        }
                    }
                }
            }
        }
        buf += 1;
    }

    //printf("B3gSearch2: after 2byte cnt %" PRIu32 "\n", cnt);
    if (ctx->scan_x_pat_cnt) {
        /* Pass bufmin on because buf no longer points to the
         * start of the buffer. */
        cnt += ctx->MBScan(mpm_ctx, mpm_thread_ctx, pmq, bufmin, buflen);
        //printf("B3gSearch1: after 2+byte cnt %" PRIu32 "\n", cnt);
    }
    return cnt;
}
uint32_t B3gScan1(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx, PatternMatcherQueue *pmq, uint8_t *buf, uint16_t buflen) {
    B3gCtx *ctx = (B3gCtx *)mpm_ctx->ctx;
    uint8_t *bufmin = buf;
    uint8_t *bufend = buf + buflen - 1;
    uint32_t cnt = 0;
    B3gPattern *p;
    B3gHashItem *thi, *hi;

    if (buflen == 0)
        return 0;

    //printf("BUF "); prt(buf,buflen); printf("\n");

    while (buf <= bufend) {
        uint8_t h = u8_tolower(*buf);
        hi = &ctx->scan_hash1[h];

        if (hi->flags & 0x01) {
            for (thi = hi; thi != NULL; thi = thi->nxt) {
                p = ctx->parray[thi->idx];

                if (p->len != 1)
                    continue;

                if (p->flags & B3G_NOCASE) {
                    if (u8_tolower(*buf) == p->ci[0]) {
                        cnt += MpmVerifyMatch(mpm_thread_ctx, pmq, p->em, (buf+1 - bufmin), p->len);
                    }
                } else {
                    if (*buf == p->cs[0]) {
                        cnt += MpmVerifyMatch(mpm_thread_ctx, pmq, p->em, (buf+1 - bufmin), p->len);
                    }
                }
            }
        }
        buf += 1;
    }

    if (ctx->scan_2_pat_cnt) {
        /* Pass bufmin on because buf no longer points to the
         * start of the buffer. */
        cnt += ctx->MBScan2(mpm_ctx, mpm_thread_ctx, pmq, bufmin, buflen);
    } else if (ctx->scan_x_pat_cnt) {
        cnt += ctx->MBScan(mpm_ctx, mpm_thread_ctx, pmq, bufmin, buflen);
    }
    return cnt;
}

/*
 * TESTS
 */

#ifdef UNITTESTS
static int B3gTestInit01 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmInitCtx(&mpm_ctx, MPM_B3G, -1);
    B3gCtx *ctx = (B3gCtx *)mpm_ctx.ctx;

    B3gAddScanPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0); /* 1 match */

    B3gPreparePatterns(&mpm_ctx);

    if (ctx->scan_m == 4)
        result = 1;
    else
        printf("4 != %" PRIu32 " ", ctx->scan_m);

    B3gDestroyCtx(&mpm_ctx);
    return result;
}

#if 0
static int B3gTestS0Init01 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmInitCtx(&mpm_ctx, MPM_B3G, -1);
    B3gCtx *ctx = (B3gCtx *)mpm_ctx.ctx;

    B3gAddScanPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0); /* 1 match */

    B3gPreparePatterns(&mpm_ctx);

    if (ctx->scan_s0 == 4)
        result = 1;
    else
        printf("4 != %" PRIu32 " ", ctx->scan_s0);

    B3gDestroyCtx(&mpm_ctx);
    return result;
}

static int B3gTestS0Init02 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmInitCtx(&mpm_ctx, MPM_B3G, -1);
    B3gCtx *ctx = (B3gCtx *)mpm_ctx.ctx;

    B3gAddScanPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0); /* 1 match */
    B3gAddScanPatternCS(&mpm_ctx, (uint8_t *)"cdef", 4, 0, 0, 1, 0); /* 1 match */

    B3gPreparePatterns(&mpm_ctx);

    if (ctx->scan_s0 == 2)
        result = 1;
    else
        printf("2 != %" PRIu32 " ", ctx->scan_s0);

    B3gDestroyCtx(&mpm_ctx);
    return result;
}

static int B3gTestS0Init03 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmInitCtx(&mpm_ctx, MPM_B3G, -1);
    B3gCtx *ctx = (B3gCtx *)mpm_ctx.ctx;

    B3gAddScanPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0); /* 1 match */
    B3gAddScanPatternCS(&mpm_ctx, (uint8_t *)"bcde", 4, 0, 0, 1, 0); /* 1 match */

    B3gPreparePatterns(&mpm_ctx);

    if (ctx->scan_s0 == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ", ctx->scan_s0);

    B3gDestroyCtx(&mpm_ctx);
    return result;
}

static int B3gTestS0Init04 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmInitCtx(&mpm_ctx, MPM_B3G, -1);
    B3gCtx *ctx = (B3gCtx *)mpm_ctx.ctx;

    B3gAddScanPatternCS(&mpm_ctx, (uint8_t *)"abab", 4, 0, 0, 0, 0); /* 1 match */

    B3gPreparePatterns(&mpm_ctx);

    if (ctx->scan_s0 == 2)
        result = 1;
    else
        printf("2 != %" PRIu32 " ", ctx->scan_s0);

    B3gDestroyCtx(&mpm_ctx);
    return result;
}

static int B3gTestS0Init05 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmInitCtx(&mpm_ctx, MPM_B3G, -1);
    B3gCtx *ctx = (B3gCtx *)mpm_ctx.ctx;

    B3gAddScanPatternCS(&mpm_ctx, (uint8_t *)"abcab", 5, 0, 0, 0, 0); /* 1 match */

    B3gPreparePatterns(&mpm_ctx);

    if (ctx->scan_s0 == 3)
        result = 1;
    else
        printf("3 != %" PRIu32 " ", ctx->scan_s0);

    B3gDestroyCtx(&mpm_ctx);
    return result;
}
#endif

static int B3gTestScan01 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B3G, -1);
    B3gCtx *ctx = (B3gCtx *)mpm_ctx.ctx;

    B3gAddScanPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0); /* 1 match */

    B3gPreparePatterns(&mpm_ctx);
    B3gThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Scan(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"abcdefghjiklmnopqrstuvwxyz", 26);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B3gThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B3gDestroyCtx(&mpm_ctx);
    return result;
}

static int B3gTestScan02 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B3G, -1);
    B3gCtx *ctx = (B3gCtx *)mpm_ctx.ctx;

    B3gAddScanPatternCS(&mpm_ctx, (uint8_t *)"abce", 4, 0, 0, 0, 0, 0); /* 1 match */

    B3gPreparePatterns(&mpm_ctx);
    B3gThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Scan(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"abcdefghjiklmnopqrstuvwxyz", 26);

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ",cnt);

    B3gThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B3gDestroyCtx(&mpm_ctx);
    return result;
}

static int B3gTestScan03 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B3G, -1);
    B3gCtx *ctx = (B3gCtx *)mpm_ctx.ctx;

    B3gAddScanPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0); /* 1 match */
    B3gAddScanPatternCS(&mpm_ctx, (uint8_t *)"bcde", 4, 0, 0, 1, 0, 0); /* 1 match */
    B3gAddScanPatternCS(&mpm_ctx, (uint8_t *)"fghj", 4, 0, 0, 2, 0, 0); /* 1 match */

    B3gPreparePatterns(&mpm_ctx);
    B3gThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 3 /* 3 patterns */);

    uint32_t cnt = ctx->Scan(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"abcdefghjiklmnopqrstuvwxyz", 26);

    if (cnt == 3)
        result = 1;
    else
        printf("3 != %" PRIu32 " ",cnt);

    B3gThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B3gDestroyCtx(&mpm_ctx);
    return result;
}

/* test patterns longer than 'm'. M is 4 here. */
static int B3gTestScan04 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B3G, -1);
    B3gCtx *ctx = (B3gCtx *)mpm_ctx.ctx;

    B3gAddScanPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0); /* 1 match */
    B3gAddScanPatternCS(&mpm_ctx, (uint8_t *)"bcdegh", 6, 0, 0, 1, 0, 0); /* 1 match */
    B3gAddScanPatternCS(&mpm_ctx, (uint8_t *)"fghjxyz", 7, 0, 0, 2, 0, 0); /* 1 match */

    B3gPreparePatterns(&mpm_ctx);
    B3gThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 3 /* 3 patterns */);

    uint32_t cnt = ctx->Scan(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"abcdefghjiklmnopqrstuvwxyz", 26);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B3gThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B3gDestroyCtx(&mpm_ctx);
    return result;
}

/* case insensitive test patterns longer than 'm'. M is 4 here. */
static int B3gTestScan05 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B3G, -1);
    B3gCtx *ctx = (B3gCtx *)mpm_ctx.ctx;

    B3gAddScanPatternCI(&mpm_ctx, (uint8_t *)"ABCD", 4, 0, 0, 0, 0, 0); /* 1 match */
    B3gAddScanPatternCI(&mpm_ctx, (uint8_t *)"bCdEfG", 6, 0, 0, 1, 0, 0); /* 1 match */
    B3gAddScanPatternCI(&mpm_ctx, (uint8_t *)"fghJikl", 7, 0, 0, 2, 0, 0); /* 1 match */

    B3gPreparePatterns(&mpm_ctx);
    B3gThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 3 /* 3 patterns */);

    uint32_t cnt = ctx->Scan(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"abcdefghjiklmnopqrstuvwxyz", 26);

    if (cnt == 3)
        result = 1;
    else
        printf("3 != %" PRIu32 " ",cnt);

    B3gThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B3gDestroyCtx(&mpm_ctx);
    return result;
}

static int B3gTestScan06 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B3G, -1);
    B3gCtx *ctx = (B3gCtx *)mpm_ctx.ctx;

    B3gAddScanPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0); /* 1 match */

    B3gPreparePatterns(&mpm_ctx);
    B3gThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Scan(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"abcd", 4);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B3gThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B3gDestroyCtx(&mpm_ctx);
    return result;
}

static int B3gTestScan07 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B3G, -1);
    B3gCtx *ctx = (B3gCtx *)mpm_ctx.ctx;

    B3gAddScanPatternCS(&mpm_ctx, (uint8_t *)"A", 1, 0, 0, 0, 0, 0); /* should match 30 times */
    B3gAddScanPatternCS(&mpm_ctx, (uint8_t *)"AA", 2, 0, 0, 1, 0, 0); /* should match 29 times */
    B3gAddScanPatternCS(&mpm_ctx, (uint8_t *)"AAA", 3, 0, 0, 2, 0, 0); /* should match 28 times */
    B3gAddScanPatternCS(&mpm_ctx, (uint8_t *)"AAAAA", 5, 0, 0, 3, 0, 0); /* 26 */
    B3gAddScanPatternCS(&mpm_ctx, (uint8_t *)"AAAAAAAAAA", 10, 0, 0, 4, 0, 0); /* 21 */
    B3gAddScanPatternCS(&mpm_ctx, (uint8_t *)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 30, 0, 0, 5, 0, 0); /* 1 */
    /* total matches: 135 */

    B3gPreparePatterns(&mpm_ctx);
    B3gThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 6 /* 6 patterns */);

    uint32_t cnt = ctx->Scan(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", 30);

    if (cnt == 135)
        result = 1;
    else
        printf("135 != %" PRIu32 " ",cnt);

    B3gThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B3gDestroyCtx(&mpm_ctx);
    return result;
}

static int B3gTestScan08 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B3G, -1);
    B3gCtx *ctx = (B3gCtx *)mpm_ctx.ctx;

    B3gAddScanPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0); /* 1 match */

    B3gPreparePatterns(&mpm_ctx);
    B3gThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Scan(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"a", 1);

    if (cnt == 0)
        result = 1;
    else
        printf("0 != %" PRIu32 " ",cnt);

    B3gThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B3gDestroyCtx(&mpm_ctx);
    return result;
}

static int B3gTestScan09 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B3G, -1);
    B3gCtx *ctx = (B3gCtx *)mpm_ctx.ctx;

    B3gAddScanPatternCS(&mpm_ctx, (uint8_t *)"ab", 2, 0, 0, 0, 0, 0); /* 1 match */

    B3gPreparePatterns(&mpm_ctx);
    B3gThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Scan(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"ab", 2);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B3gThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B3gDestroyCtx(&mpm_ctx);
    return result;
}

static int B3gTestScan10 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B3G, -1);
    B3gCtx *ctx = (B3gCtx *)mpm_ctx.ctx;

    B3gAddScanPatternCS(&mpm_ctx, (uint8_t *)"abcdefgh", 8, 0, 0, 0, 0, 0); /* 1 match */

    B3gPreparePatterns(&mpm_ctx);
    B3gThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1 /* 1 pattern */);

    uint32_t cnt = ctx->Scan(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"012345679012345679012345679012345679012345679012345679012345679012345679012345679012345679abcdefgh012345679012345679012345679012345679012345679012345679012345679012345679012345679012345679", 208);

    if (cnt == 1)
        result = 1;
    else
        printf("1 != %" PRIu32 " ",cnt);

    B3gThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B3gDestroyCtx(&mpm_ctx);
    return result;
}

static int B3gTestScan11 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B3G, -1);
    B3gCtx *ctx = (B3gCtx *)mpm_ctx.ctx;

    B3gAddScanPatternCS(&mpm_ctx, (uint8_t *)"abcd", 4, 0, 0, 0, 0, 0); /* 1 match */
    B3gAddScanPatternCS(&mpm_ctx, (uint8_t *)"abcde", 5, 0, 0, 0, 0, 0); /* 1 match */

    B3gPreparePatterns(&mpm_ctx);
    B3gThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 2 /* 2 patterns */);

    uint32_t cnt = ctx->Scan(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"abcdefghjiklmnopqrstuvwxyz", 26);

    if (cnt == 2)
        result = 1;
    else
        printf("2 != %" PRIu32 " ",cnt);

    B3gThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B3gDestroyCtx(&mpm_ctx);
    return result;
}

static int B3gTestScan12 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    memset(&mpm_ctx, 0x00, sizeof(MpmCtx));
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_B3G, -1);
    B3gCtx *ctx = (B3gCtx *)mpm_ctx.ctx;

    B3gAddScanPatternCS(&mpm_ctx, (uint8_t *)"wxyz", 4, 0, 0, 0, 0, 0); /* 1 match */
    B3gAddScanPatternCS(&mpm_ctx, (uint8_t *)"vwxyz", 5, 0, 0, 0, 0, 0); /* 1 match */

    B3gPreparePatterns(&mpm_ctx);
    B3gThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 2 /* 2 patterns */);

    uint32_t cnt = ctx->Scan(&mpm_ctx, &mpm_thread_ctx, NULL, (uint8_t *)"abcdefghjiklmnopqrstuvwxyz", 26);

    if (cnt == 2)
        result = 1;
    else
        printf("2 != %" PRIu32 " ",cnt);

    B3gThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    B3gDestroyCtx(&mpm_ctx);
    return result;
}

#endif /* UNITTESTS */

void B3gRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("B3gTestInit01", B3gTestInit01, 1);
/*
    UtRegisterTest("B3gTestS0Init01", B3gTestS0Init01, 1);
    UtRegisterTest("B3gTestS0Init02", B3gTestS0Init02, 1);
    UtRegisterTest("B3gTestS0Init03", B3gTestS0Init03, 1);
    UtRegisterTest("B3gTestS0Init04", B3gTestS0Init04, 1);
    UtRegisterTest("B3gTestS0Init05", B3gTestS0Init05, 1);
*/
    UtRegisterTest("B3gTestScan01", B3gTestScan01, 1);

    UtRegisterTest("B3gTestScan02", B3gTestScan02, 1);
    UtRegisterTest("B3gTestScan03", B3gTestScan03, 1);
    UtRegisterTest("B3gTestScan04", B3gTestScan04, 1);
    UtRegisterTest("B3gTestScan05", B3gTestScan05, 1);
    UtRegisterTest("B3gTestScan06", B3gTestScan06, 1);
    UtRegisterTest("B3gTestScan07", B3gTestScan07, 1);
    UtRegisterTest("B3gTestScan08", B3gTestScan08, 1);
    UtRegisterTest("B3gTestScan09", B3gTestScan09, 1);
    UtRegisterTest("B3gTestScan10", B3gTestScan10, 1);
    UtRegisterTest("B3gTestScan11", B3gTestScan11, 1);
    UtRegisterTest("B3gTestScan12", B3gTestScan12, 1);
#endif /* UNITTESTS */
}


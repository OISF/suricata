/* Implementation of the Wu-Manber pattern matching algorithm.
 *
 * Copyright (c) 2008 Victor Julien <victor@inliniac.net>
 *
 * Ideas:
 *   - the hash contains a list of patterns. Maybe we can 'train' the hash
 *     so the most common patterns always appear first in this list.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include "util-mpm.h"
#include "util-mpm-wumanber.h"

#include "util-unittest.h"

void WmInitCtx (MpmCtx *mpm_ctx);
void WmThreadInitCtx(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx, u_int32_t);
void WmDestroyCtx(MpmCtx *mpm_ctx);
void WmThreadDestroyCtx(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx);
int WmAddPatternCI(MpmCtx *mpm_ctx, u_int8_t *pat, u_int16_t patlen, u_int32_t id);
int WmAddPatternCS(MpmCtx *mpm_ctx, u_int8_t *pat, u_int16_t patlen, u_int32_t id);
int WmPreparePatterns(MpmCtx *mpm_ctx);
u_int32_t WmSearch1(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx, u_int8_t *buf, u_int16_t buflen);
u_int32_t WmSearch2(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx, u_int8_t *buf, u_int16_t buflen);
void WmPrintInfo(MpmCtx *mpm_ctx);
void WmPrintSearchStats(MpmThreadCtx *mpm_thread_ctx);
void WmRegisterTests(void);

/* uppercase to lowercase conversion lookup table */
static u_int8_t lowercasetable[256];
/* marco to do the actual lookup */
#define wm_tolower(c) lowercasetable[(c)]

void MpmWuManberRegister (void) {
    mpm_table[MPM_WUMANBER].name = "wumanber";
    mpm_table[MPM_WUMANBER].InitCtx = WmInitCtx;
    mpm_table[MPM_WUMANBER].InitThreadCtx = WmThreadInitCtx;
    mpm_table[MPM_WUMANBER].DestroyCtx = WmDestroyCtx;
    mpm_table[MPM_WUMANBER].DestroyThreadCtx = WmThreadDestroyCtx;
    mpm_table[MPM_WUMANBER].AddPattern = WmAddPatternCS;
    mpm_table[MPM_WUMANBER].AddPatternNocase = WmAddPatternCI;
    mpm_table[MPM_WUMANBER].Prepare = WmPreparePatterns;
    mpm_table[MPM_WUMANBER].Search = WmSearch2; /* default to WmSearch2. We may fall back to 1 */
    mpm_table[MPM_WUMANBER].Cleanup = MpmMatchCleanup;
    mpm_table[MPM_WUMANBER].PrintCtx = WmPrintInfo;
    mpm_table[MPM_WUMANBER].PrintThreadCtx = WmPrintSearchStats;
    mpm_table[MPM_WUMANBER].RegisterUnittests = WmRegisterTests;

    /* create table for O(1) lowercase conversion lookup */
    u_int8_t c = 0;
    for ( ; c < 255; c++) {
       if (c >= 'A' && c <= 'Z')
           lowercasetable[c] = (c + ('a' - 'A'));
       else
           lowercasetable[c] = c;
    }
}

/* append an endmatch to a pattern
 *
 * Only used in the initialization phase */
static void WmEndMatchAppend(MpmCtx *mpm_ctx, WmPattern *p,  u_int32_t id)
{
    MpmEndMatch *em = MpmAllocEndMatch(mpm_ctx);
    if (em == NULL) {
        printf("ERROR: WmAllocEndMatch failed\n");
        return;
    }

    em->id = id;

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

void prt (u_int8_t *buf, u_int16_t buflen) {
    u_int16_t i;

    for (i = 0; i < buflen; i++) {
        if (isprint(buf[i])) printf("%c", buf[i]);
        else                 printf("\\x%X", buf[i]);
    }
    //printf("\n");
}

void WmPrintInfo(MpmCtx *mpm_ctx) {
    WmCtx *wm_ctx = (WmCtx *)mpm_ctx->ctx;

    printf("MPM WuManber Information:\n");
    printf("Memory allocs:   %u\n", mpm_ctx->memory_cnt);
    printf("Memory alloced:  %u\n", mpm_ctx->memory_size);
    printf("Unique Patterns: %u\n", mpm_ctx->pattern_cnt);
    printf("Total Patterns:  %u\n", mpm_ctx->total_pattern_cnt);
    printf("Smallest:        %u\n", mpm_ctx->minlen);
    printf("Largest:         %u\n", mpm_ctx->maxlen);
    printf("Max shiftlen:    %u\n", wm_ctx->shiftlen);
    printf("Search function: ");
    if (mpm_ctx->Search == WmSearch1) printf("WmSearch1 (allows single byte patterns)\n");
    else if (mpm_ctx->Search == WmSearch2) printf("WmSearch2 (only for multibyte patterns)\n");
    else printf("ERROR\n");
    printf("\n");
}

WmPattern *WmAllocPattern(MpmCtx *mpm_ctx) {
    WmPattern *p = malloc(sizeof(WmPattern));
    if (p == NULL) {
        printf("ERROR: WmAllocPattern: malloc failed\n");
    }

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += sizeof(WmPattern);

    p->cs = NULL;
    p->ci = NULL;
    p->len = 0;
    p->next = NULL;
    p->flags = 0;
    p->prefix_ci = 0;
    p->prefix_cs = 0;
    p->em = NULL;
    return p;
}

static WmHashItem *
WmAllocHashItem(MpmCtx *mpm_ctx) {
    WmHashItem *hi = malloc(sizeof(WmHashItem));
    if (hi == NULL) {
        printf("ERROR: WmAllocHashItem: malloc failed\n");
    }

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += sizeof(WmHashItem);

    hi->flags = 0;
    hi->nxt = NULL;
    hi->idx = 0;
    return hi;
}

static void memcpy_tolower(u_int8_t *d, u_int8_t *s, u_int16_t len) {
    u_int16_t i;
    for (i = 0; i < len; i++) {
        d[i] = wm_tolower(s[i]);
    }
}

static int WmCmpPattern(WmPattern *p, u_int8_t *pat, u_int16_t patlen, char nocase) {
    if (p->len != patlen)
        return 0;

    if (!((nocase && p->flags & NOCASE) || (!nocase && !(p->flags & NOCASE))))
        return 0;

    if (memcmp(p->cs, pat, patlen) != 0)
        return 0;

    return 1;
}

/* See if a pattern is already included. Used when adding a pattern,
 * NOT at search runtime! */
static WmPattern *
WmSearchPattern(MpmCtx *mpm_ctx, u_int8_t *pat, u_int16_t patlen, char nocase) {
    WmCtx *wm_ctx = (WmCtx *)mpm_ctx->ctx;

    WmPattern *p = wm_ctx->head;

    while (p) {
        if (WmCmpPattern(p, pat, patlen, nocase) == 1) {
            //printf("WmSearchPattern: pattern found\n");
            return p;
        }

        p = p->next;
    }

    return NULL;
}

void WmFreePattern(MpmCtx *mpm_ctx, WmPattern *p) {
    if (p && p->em) {
        MpmEndMatchFreeAll(mpm_ctx, p->em);
    }

    if (p && p->cs) {
        free(p->cs);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= p->len;
    }

    if (p && p->ci) {
        free(p->ci);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= p->len;
    }

    if (p) {
        free(p);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= sizeof(WmPattern); 
    }
}

int WmAddPattern(MpmCtx *mpm_ctx, u_int8_t *pat, u_int16_t patlen, char nocase, u_int32_t id) {
    WmCtx *wm_ctx = (WmCtx *)mpm_ctx->ctx;

    //printf("WmAddPattern: ctx %p \"", mpm_ctx); prt(pat, patlen);
    //printf("\" id %u, nocase %s\n", id, nocase ? "true" : "false");

    if (patlen == 0)
        return 0;

    /* get a memory piece */
    WmPattern *p = WmSearchPattern(mpm_ctx, pat, patlen, nocase);
    if (p == NULL) {
        //printf("WmAddPattern: allocing new pattern\n");
        p = WmAllocPattern(mpm_ctx);
        if (p == NULL)
            goto error;

        p->len = patlen;

        /* setup the case sensitive part of the pattern */
        p->cs = malloc(patlen);
        if (p->cs == NULL) goto error;
        mpm_ctx->memory_cnt++;
        mpm_ctx->memory_size += patlen;
        memcpy(p->cs, pat, patlen);

        /* setup the case insensitive part of the pattern */
        p->ci = malloc(patlen);
        if (p->ci == NULL) goto error;
        mpm_ctx->memory_cnt++;
        mpm_ctx->memory_size += patlen;
        memcpy_tolower(p->ci, pat, patlen);

        if (p->len > 1) {
            p->prefix_cs = (u_int16_t)(*(p->cs)+*(p->cs+1));
            p->prefix_ci = (u_int16_t)(*(p->ci)+*(p->ci+1));
        }

        if (nocase) p->flags |= NOCASE;

        //printf("WmAddPattern: ci \""); prt(p->ci,p->len);
        //printf("\" cs \""); prt(p->cs,p->len);
        //printf("\" prefix_ci %u, prefix_cs %u\n", p->prefix_ci, p->prefix_cs);

        /* put in the pattern list */
        if (wm_ctx->head == NULL) wm_ctx->head = p;
        if (wm_ctx->tail) wm_ctx->tail->next = p;
        wm_ctx->tail = p;

        if (mpm_ctx->pattern_cnt == 65535) {
            printf("Max search words reached\n");
            exit(1);
        }
        mpm_ctx->pattern_cnt++;

        if (mpm_ctx->maxlen < patlen) mpm_ctx->maxlen = patlen;
        if (mpm_ctx->pattern_cnt == 1) mpm_ctx->minlen = patlen;
        else if (mpm_ctx->minlen > patlen) mpm_ctx->minlen = patlen;
    }

    /* we need a match */
    WmEndMatchAppend(mpm_ctx, p, id);

    /* keep track of highest pattern id */
    if (id > mpm_ctx->max_pattern_id)
        mpm_ctx->max_pattern_id = id;

    mpm_ctx->total_pattern_cnt++;

    return 0;

error:
    WmFreePattern(mpm_ctx, p);
    return -1;
}

int WmAddPatternCI(MpmCtx *mpm_ctx, u_int8_t *pat, u_int16_t patlen, u_int32_t id) {
    return WmAddPattern(mpm_ctx, pat, patlen, 1, id);
}

int WmAddPatternCS(MpmCtx *mpm_ctx, u_int8_t *pat, u_int16_t patlen, u_int32_t id) {
    return WmAddPattern(mpm_ctx, pat, patlen, 0, id);
}

#define HASH_SIZE 65536
#define HASH(b) (((*(b))<<8) | *((b)+1))

static void WmPrepareHash(MpmCtx *mpm_ctx) {
    WmCtx *wm_ctx = (WmCtx *)mpm_ctx->ctx;
    u_int16_t i;
    u_int16_t idx = 0;
    u_int8_t idx8 = 0;

    wm_ctx->hash = (WmHashItem *)malloc(sizeof(WmHashItem) * HASH_SIZE);
    if (wm_ctx->hash == NULL) goto error;
    memset(wm_ctx->hash, 0, sizeof(WmHashItem) * HASH_SIZE);

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += (sizeof(WmHashItem) * HASH_SIZE);

    for (i = 0; i < mpm_ctx->pattern_cnt; i++)
    {
        if(wm_ctx->parray[i].len == 1) {
            idx8 = (u_int8_t)wm_ctx->parray[i].ci[0];
            if (wm_ctx->hash1[idx8].flags == 0) {
                wm_ctx->hash1[idx8].idx = i;
                wm_ctx->hash1[idx8].flags |= 0x01;
            } else {
                WmHashItem *hi = WmAllocHashItem(mpm_ctx);
                hi->idx = i;
                hi->flags |= 0x01;

                /* Append this HashItem to the list */
                WmHashItem *thi = &wm_ctx->hash1[idx8];
                while (thi->nxt) thi = thi->nxt;
                thi->nxt = hi;
            }
        } else {
            u_int16_t patlen = wm_ctx->shiftlen;

            idx = ((wm_ctx->parray[i].ci[patlen-1]<<8) + (wm_ctx->parray[i].ci[patlen-2]));
            if (wm_ctx->hash[idx].flags == 0) {
                wm_ctx->hash[idx].idx = i;
                wm_ctx->hash[idx].flags |= 0x01;
            } else {
                WmHashItem *hi = WmAllocHashItem(mpm_ctx);
                hi->idx = i;
                hi->flags |= 0x01;

                /* Append this HashItem to the list */
                WmHashItem *thi = &wm_ctx->hash[idx];
                while (thi->nxt) thi = thi->nxt;
                thi->nxt = hi;
            }
        }
    }
    return;
error:
    return;
}

static void WmPrepareShiftTable(MpmCtx *mpm_ctx)
{
    WmCtx *wm_ctx = (WmCtx *)mpm_ctx->ctx;

    u_int16_t shift = 0, k = 0, idx = 0;
    u_int32_t i = 0;

    u_int16_t smallest = mpm_ctx->minlen;
    if (smallest > 255) smallest = 255;
    if (smallest < 2) smallest = 2;

    wm_ctx->shiftlen = smallest;

    /* default shift table is set to minimal shift */
    for (i = 0; i < 65536; i++)
        wm_ctx->shifttable[i] = wm_ctx->shiftlen - 1;

    for (i = 0; i < mpm_ctx->pattern_cnt; i++)
    {
        /* ignore one byte patterns */
        if (wm_ctx->parray[i].len == 1)
            continue;

        //printf("WmPrepareShiftTable: i = %u ", i);
        //prt(wm_ctx->parray[i].ci, wm_ctx->parray[i].len);

        for (k = 0; k < wm_ctx->shiftlen-1; k++)
        {
            shift = (wm_ctx->shiftlen - 2 - k);
            if (shift > 255) shift = 255;

            idx = ((wm_ctx->parray[i].ci[k]) | (wm_ctx->parray[i].ci[k+1]<<8));
            if (shift < wm_ctx->shifttable[idx]) {
                wm_ctx->shifttable[idx] = shift;
            }
            //printf("WmPrepareShiftTable: i %u, k %u, idx %u, shift set to %u: \"%c%c\"\n",
            //    i, k, idx, shift, wm_ctx->parray[i].ci[k], wm_ctx->parray[i].ci[k+1]);
        }
    }
}

int WmPreparePatterns(MpmCtx *mpm_ctx) {
    WmCtx *wm_ctx = (WmCtx *)mpm_ctx->ctx;

    /* alloc the pattern array */
    wm_ctx->parray = malloc(mpm_ctx->pattern_cnt * sizeof(WmPattern));
    if (wm_ctx->parray == NULL) goto error;
    memset(wm_ctx->parray, 0, mpm_ctx->pattern_cnt * sizeof(WmPattern));
    //printf("mpm_ctx %p, parray %p\n", mpm_ctx,wm_ctx->parray);
    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += (mpm_ctx->pattern_cnt * sizeof(WmPattern));

    /* populate it */
    u_int16_t i = 0;
    WmPattern *node = wm_ctx->head;
    while (node != NULL) {
        //printf("i %u: node->ci %s\n", i, node->ci);
        memcpy(&wm_ctx->parray[i], node, sizeof(WmPattern));
        node = node->next; i++;
    }

    WmPrepareShiftTable(mpm_ctx);
    WmPrepareHash(mpm_ctx);

    if (mpm_ctx->minlen == 1)
        mpm_ctx->Search = WmSearch1;

    return 0;
error:
    return -1;
}

void WmPrintSearchStats(MpmThreadCtx *mpm_thread_ctx) {
    WmThreadCtx *wm_thread_ctx = (WmThreadCtx *)mpm_thread_ctx->ctx;

    printf("Shift 0: %u\n", wm_thread_ctx->stat_shift_null);
    printf("Loop match: %u\n", wm_thread_ctx->stat_loop_match);
    printf("Loop no match: %u\n", wm_thread_ctx->stat_loop_no_match);
    printf("Num shifts: %u\n", wm_thread_ctx->stat_num_shift);
    printf("Total shifts: %u\n", wm_thread_ctx->stat_total_shift);
}

static inline int
memcmp_lowercase(u_int8_t *s1, u_int8_t *s2, u_int16_t n) {
    size_t i;

    /* check backwards because we already tested the first
     * 2 to 4 chars. This way we are more likely to detect
     * a miss and thus speed up a little... */
    for (i = n - 1; i; i--) {
        if (wm_tolower(*(s2+i)) != s1[i])
            return 1;
    }

    return 0;
}


u_int32_t WmSearch2(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx, u_int8_t *buf, u_int16_t buflen) {
    WmCtx *wm_ctx = (WmCtx *)mpm_ctx->ctx;
    WmThreadCtx *wm_thread_ctx = (WmThreadCtx *)mpm_thread_ctx->ctx;

    u_int32_t cnt = 0;
    u_int8_t *bufmin = buf;
    u_int8_t *bufend = buf + buflen - 1;
    u_int16_t sl = wm_ctx->shiftlen;
    u_int16_t h;
    u_int8_t shift;
    WmHashItem *thi, *hi;
    WmPattern *p;
    u_int16_t prefixci_buf;
    u_int16_t prefixcs_buf;

    if (buflen == 0)
        return 0;

    //printf("BUF(%u) ", buflen); prt(buf,buflen); printf("\n");

    buf++;

    while (buf <= bufend) {
        h = (wm_tolower(*buf)<<8)+(wm_tolower(*(buf-1)));
        shift = wm_ctx->shifttable[h];

        if (shift == 0) {
            wm_thread_ctx->stat_shift_null++;
            /* get our hash item */
            hi = &wm_ctx->hash[h];
            prefixci_buf = (u_int16_t)(wm_tolower(*(buf-sl+1)) + wm_tolower(*(buf-sl+2)));
            prefixcs_buf = (u_int16_t)(*(buf-sl+1) + *(buf-sl+2));
            //printf("WmSearch2: prefixci_buf %u, prefixcs_buf %u\n", prefixci_buf, prefixcs_buf);
            for (thi = hi; thi != NULL; thi = thi->nxt) {
                p = &wm_ctx->parray[thi->idx];

                //printf("WmSearch2: p->prefix_ci %u, p->prefix_cs %u\n",
                //    p->prefix_ci, p->prefix_cs);

                if (p->flags & NOCASE) {
                    if (p->prefix_ci != prefixci_buf || p->len > (bufend-(buf-sl)))
                        continue;

                    if (memcmp_lowercase(p->ci, buf-sl+1, p->len) == 0) {
                        cnt++;
                        //printf("CI Exact match: "); prt(p->ci, p->len); printf("\n");
                        wm_thread_ctx->stat_loop_match++;

                        MpmEndMatch *em; 
                        for (em = p->em; em; em = em->next) {
                            //printf("em %p id %u\n", em, em->id);
                            MpmMatchAppend(mpm_thread_ctx, em, &mpm_thread_ctx->match[em->id],(buf-sl+1 - bufmin));
                        }

                    } else {
                        wm_thread_ctx->stat_loop_no_match++;
                    }
                } else {
                    if (p->prefix_cs != prefixcs_buf || p->len > (bufend-(buf-sl)))
                        continue;
                    if (memcmp(p->cs, buf-sl+1, p->len) == 0) {
                        cnt++;
                        //printf("CS Exact match: "); prt(p->cs, p->len); printf("\n");
                        wm_thread_ctx->stat_loop_match++;

                        MpmEndMatch *em; 
                        for (em = p->em; em; em = em->next) {
                            //printf("em %p id %u\n", em, em->id);
                            MpmMatchAppend(mpm_thread_ctx, em, &mpm_thread_ctx->match[em->id],(buf-sl+1 - bufmin));
                        }

                    } else {
                        wm_thread_ctx->stat_loop_no_match++;
                    }
                }
            }
            shift = 1;
        } else {
            wm_thread_ctx->stat_total_shift += shift;
            wm_thread_ctx->stat_num_shift++;
        }
        buf += shift;
    }

    return cnt;
}

u_int32_t WmSearch1(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx, u_int8_t *buf, u_int16_t buflen) {
    WmCtx *wm_ctx = (WmCtx *)mpm_ctx->ctx;
    //WmThreadCtx *wm_thread_ctx = (WmThreadCtx *)mpm_thread_ctx->ctx;

    u_int8_t *bufmin = buf;
    u_int8_t *bufend = buf + buflen - 1;
    u_int32_t cnt = 0;
    WmPattern *p;
    MpmEndMatch *em; 
    WmHashItem *thi, *hi;

    if (buflen == 0)
        return 0;

    //printf("BUF "); prt(buf,buflen); printf("\n");

    if (mpm_ctx->minlen == 1) {
        while (buf <= bufend) {
            u_int8_t h = wm_tolower(*buf);
            hi = &wm_ctx->hash1[h];

            if (hi->flags & 0x01) {
                for (thi = hi; thi != NULL; thi = thi->nxt) {
                    p = &wm_ctx->parray[thi->idx];

                    if (p->len != 1)
                        continue;

                    if (p->flags & NOCASE) {
                        if (wm_tolower(*buf) == p->ci[0]) {
                            //printf("CI Exact match: "); prt(p->ci, p->len); printf(" in buf "); prt(buf, p->len);printf(" (WmSearch1)\n");
                            for (em = p->em; em; em = em->next) {
                                MpmMatchAppend(mpm_thread_ctx, em, &mpm_thread_ctx->match[em->id],(buf+1 - bufmin));
                            }

                            cnt++;
                        }
                    } else {
                        if (*buf == p->cs[0]) {
                            //printf("CS Exact match: "); prt(p->cs, p->len); printf(" in buf "); prt(buf, p->len);printf(" (WmSearch1)\n");
                            for (em = p->em; em; em = em->next) {
                                MpmMatchAppend(mpm_thread_ctx, em, &mpm_thread_ctx->match[em->id],(buf+1 - bufmin));
                            }
                            cnt++;
                        }
                    }
                }
            }
            buf += 1;
        }
    }
    //printf("WmSearch1: after 1byte cnt %u\n", cnt);
    if (mpm_ctx->maxlen > 1) {
        /* Pass bufmin on because buf no longer points to the
         * start of the buffer. */
        cnt += WmSearch2(mpm_ctx, mpm_thread_ctx, bufmin, buflen);
        //printf("WmSearch1: after 2+byte cnt %u\n", cnt);
    }
    return cnt;
}

void WmInitCtx (MpmCtx *mpm_ctx) {
    //printf("WmInitCtx: mpm_ctx %p\n", mpm_ctx);

    memset(mpm_ctx, 0, sizeof(MpmCtx));

    mpm_ctx->ctx = malloc(sizeof(WmCtx));
    if (mpm_ctx->ctx == NULL)
        return;

    memset(mpm_ctx->ctx, 0, sizeof(WmCtx));

    mpm_ctx->memory_cnt++;
    mpm_ctx->memory_size += sizeof(WmCtx);
}

void WmDestroyCtx(MpmCtx *mpm_ctx) {
    WmCtx *wm_ctx = (WmCtx *)mpm_ctx->ctx;
    if (wm_ctx != NULL) {
        WmPattern *p = wm_ctx->head, *tp;
        while (p) {
           tp = p->next;
           WmFreePattern(mpm_ctx,p);
           p = tp;
        }

        if (wm_ctx->parray) {
            free(wm_ctx->parray);
            mpm_ctx->memory_cnt--;
            mpm_ctx->memory_size -= sizeof(mpm_ctx->pattern_cnt * sizeof(WmPattern));
        }

        if (wm_ctx->hash) {
            free(wm_ctx->hash);
            mpm_ctx->memory_cnt--;
            mpm_ctx->memory_size -= sizeof(sizeof(WmHashItem) * HASH_SIZE);
        }

        free(mpm_ctx->ctx);
        mpm_ctx->memory_cnt--;
        mpm_ctx->memory_size -= sizeof(WmCtx);
    }
}

void WmThreadInitCtx(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx, u_int32_t matchsize) {
    memset(mpm_thread_ctx, 0, sizeof(MpmThreadCtx));

    mpm_thread_ctx->ctx = malloc(sizeof(WmThreadCtx));
    if (mpm_thread_ctx->ctx == NULL)
        return;

    memset(mpm_thread_ctx->ctx, 0, sizeof(WmThreadCtx));

    mpm_thread_ctx->memory_cnt++;
    mpm_thread_ctx->memory_size += sizeof(WmThreadCtx);

    /* alloc an array with the size of _all_ keys in all instances.
     * this is done so the detect engine won't have to care about
     * what instance it's looking up in. The matches all have a
     * unique id and is the array lookup key at the same time */
    //u_int32_t keys = mpm_ctx->max_pattern_id + 1;
    u_int32_t keys = matchsize + 1;
    if (keys) {
        mpm_thread_ctx->match = malloc(keys * sizeof(MpmMatchBucket));
        if (mpm_thread_ctx->match == NULL) {
            printf("ERROR: could not setup memory for pattern matcher: %s\n", strerror(errno));
            exit(1);
        }
        memset(mpm_thread_ctx->match, 0, keys * sizeof(MpmMatchBucket));

        mpm_thread_ctx->memory_cnt++;
        mpm_thread_ctx->memory_size += (keys * sizeof(MpmMatchBucket));
    }
}

void WmThreadDestroyCtx(MpmCtx *mpm_ctx, MpmThreadCtx *mpm_thread_ctx) {
    WmThreadCtx *wm_ctx = (WmThreadCtx *)mpm_thread_ctx->ctx;
    if (wm_ctx) {
        if (mpm_thread_ctx->match != NULL) {
            mpm_thread_ctx->memory_cnt--;
            mpm_thread_ctx->memory_size -= ((mpm_ctx->max_pattern_id + 1) * sizeof(MpmMatchBucket));
            free(mpm_thread_ctx->match);
        }

        mpm_thread_ctx->memory_cnt--;
        mpm_thread_ctx->memory_size -= sizeof(WmThreadCtx);
        free(mpm_thread_ctx->ctx);
    }

    MpmMatchFreeSpares(mpm_thread_ctx, mpm_thread_ctx->sparelist);
    MpmMatchFreeSpares(mpm_thread_ctx, mpm_thread_ctx->qlist);
}

/*
 * ONLY TESTS BELOW THIS COMMENT
 */


int WmTestInitCtx01 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    WmInitCtx(&mpm_ctx);

    if (mpm_ctx.ctx != NULL)
        result = 1;

    WmDestroyCtx(&mpm_ctx);
    return result;
}

int WmTestInitCtx02 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    WmInitCtx(&mpm_ctx);

    WmCtx *wm_ctx = (WmCtx *)mpm_ctx.ctx; 

    if (wm_ctx->head == NULL)
        result = 1;

    WmDestroyCtx(&mpm_ctx);
    return result;
}

int WmTestInitCtx03 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmInitCtx(&mpm_ctx, MPM_WUMANBER);

    if (mpm_ctx.Search == WmSearch2)
        result = 1;

    WmDestroyCtx(&mpm_ctx);
    return result;
}

int WmTestThreadInitCtx01 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;

    MpmInitCtx(&mpm_ctx, MPM_WUMANBER);
    WmThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1);

    if (mpm_thread_ctx.memory_cnt == 2)
        result = 1;

    WmThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    WmDestroyCtx(&mpm_ctx);
    return result;
}

int WmTestThreadInitCtx02 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;

    MpmInitCtx(&mpm_ctx, MPM_WUMANBER);
    WmThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1);

    WmThreadCtx *wm_thread_ctx = (WmThreadCtx *)mpm_thread_ctx.ctx;

    if (wm_thread_ctx->stat_shift_null == 0)
        result = 1;

    WmThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    WmDestroyCtx(&mpm_ctx);
    return result;
}

int WmTestInitAddPattern01 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;

    MpmInitCtx(&mpm_ctx, MPM_WUMANBER);
    WmThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1);

    int ret = WmAddPattern(&mpm_ctx, (u_int8_t *)"abcd", 4, 1, 1234);
    if (ret == 0)
        result = 1;

    WmThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    WmDestroyCtx(&mpm_ctx);
    return result;
}

int WmTestInitAddPattern02 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;

    MpmInitCtx(&mpm_ctx, MPM_WUMANBER);
    WmThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1);
    WmCtx *wm_ctx = (WmCtx *)mpm_ctx.ctx;

    WmAddPattern(&mpm_ctx, (u_int8_t *)"abcd", 4, 1, 1234);

    if (wm_ctx->head != NULL)
        result = 1;

    WmThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    WmDestroyCtx(&mpm_ctx);
    return result;
}

int WmTestInitAddPattern03 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;

    MpmInitCtx(&mpm_ctx, MPM_WUMANBER);
    WmThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1);
    WmCtx *wm_ctx = (WmCtx *)mpm_ctx.ctx;

    WmAddPattern(&mpm_ctx, (u_int8_t *)"abcd", 4, 1, 1234);

    WmPattern *pat = wm_ctx->head;

    if (pat->len == 4)
        result = 1;

    WmThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    WmDestroyCtx(&mpm_ctx);
    return result;
}

int WmTestInitAddPattern04 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;

    MpmInitCtx(&mpm_ctx, MPM_WUMANBER);
    WmThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1);
    WmCtx *wm_ctx = (WmCtx *)mpm_ctx.ctx;

    WmAddPattern(&mpm_ctx, (u_int8_t *)"abcd", 4, 1, 1234);

    WmPattern *pat = wm_ctx->head;

    if (pat->flags & NOCASE)
        result = 1;

    WmThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    WmDestroyCtx(&mpm_ctx);
    return result;
}

int WmTestInitAddPattern05 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;

    MpmInitCtx(&mpm_ctx, MPM_WUMANBER);
    WmThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1);
    WmCtx *wm_ctx = (WmCtx *)mpm_ctx.ctx;

    WmAddPattern(&mpm_ctx, (u_int8_t *)"abcd", 4, 0, 1234);

    WmPattern *pat = wm_ctx->head;

    if (!(pat->flags & NOCASE))
        result = 1;

    WmThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    WmDestroyCtx(&mpm_ctx);
    return result;
}

int WmTestInitAddPattern06 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;

    MpmInitCtx(&mpm_ctx, MPM_WUMANBER);
    WmThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1);
    WmCtx *wm_ctx = (WmCtx *)mpm_ctx.ctx;

    WmAddPattern(&mpm_ctx, (u_int8_t *)"abcd", 4, 1, 1234);

    WmPattern *pat = wm_ctx->head;

    if (memcmp(pat->cs, "abcd", 4) == 0)
        result = 1;

    WmThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    WmDestroyCtx(&mpm_ctx);
    return result;
}

int WmTestInitAddPattern07 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;

    MpmInitCtx(&mpm_ctx, MPM_WUMANBER);
    WmThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1);

    WmAddPattern(&mpm_ctx, (u_int8_t *)"abcd", 4, 1, 1234);

    if (mpm_ctx.max_pattern_id == 1234)
        result = 1;

    WmThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    WmDestroyCtx(&mpm_ctx);
    return result;
}

int WmTestPrepare01 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmInitCtx(&mpm_ctx, MPM_WUMANBER);

    WmAddPattern(&mpm_ctx, (u_int8_t *)"a", 1, 1, 0);
    WmPreparePatterns(&mpm_ctx);

    if (mpm_ctx.Search == WmSearch1)
        result = 1;

    WmDestroyCtx(&mpm_ctx);
    return result;
}

int WmTestSearch01 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;

    MpmInitCtx(&mpm_ctx, MPM_WUMANBER);

    WmAddPattern(&mpm_ctx, (u_int8_t *)"abcd", 4, 1, 0);
    WmPreparePatterns(&mpm_ctx);
    WmThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1);

    u_int32_t cnt = WmSearch2(&mpm_ctx, &mpm_thread_ctx, (u_int8_t *)"abcd", 4);
    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 1)
        result = 1;

    WmThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    WmDestroyCtx(&mpm_ctx);
    return result;
}

int WmTestSearch02 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_WUMANBER);

    WmAddPattern(&mpm_ctx, (u_int8_t *)"abcd", 4, 1, 0);
    WmPreparePatterns(&mpm_ctx);
    WmThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1);

    u_int32_t cnt = WmSearch2(&mpm_ctx, &mpm_thread_ctx, (u_int8_t *)"abce", 4);
    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 0)
        result = 1;

    WmThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    WmDestroyCtx(&mpm_ctx);
    return result;
}

int WmTestSearch03 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_WUMANBER);

    WmAddPattern(&mpm_ctx, (u_int8_t *)"abcd", 4, 1, 0);
    WmPreparePatterns(&mpm_ctx);
    WmThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1);

    u_int32_t cnt = WmSearch2(&mpm_ctx, &mpm_thread_ctx, (u_int8_t *)"abcdefgh", 8);
    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 1)
        result = 1;

    WmThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    WmDestroyCtx(&mpm_ctx);
    return result;
}

int WmTestSearch04 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_WUMANBER);

    WmAddPattern(&mpm_ctx, (u_int8_t *)"bcde", 4, 1, 0);
    WmPreparePatterns(&mpm_ctx);
    WmThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1);

    u_int32_t cnt = WmSearch2(&mpm_ctx, &mpm_thread_ctx, (u_int8_t *)"abcdefgh", 8);
    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 1)
        result = 1;

    WmThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    WmDestroyCtx(&mpm_ctx);
    return result;
}

int WmTestSearch05 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_WUMANBER);

    WmAddPattern(&mpm_ctx, (u_int8_t *)"efgh", 4, 1, 0);
    WmPreparePatterns(&mpm_ctx);
    WmThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1);

    u_int32_t cnt = WmSearch2(&mpm_ctx, &mpm_thread_ctx, (u_int8_t *)"abcdefgh", 8);
    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 1)
        result = 1;

    WmThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    WmDestroyCtx(&mpm_ctx);
    return result;
}

int WmTestSearch06 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_WUMANBER);

    WmAddPattern(&mpm_ctx, (u_int8_t *)"eFgH", 4, 1, 0);
    WmPreparePatterns(&mpm_ctx);
    WmThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1);

    u_int32_t cnt = WmSearch2(&mpm_ctx, &mpm_thread_ctx, (u_int8_t *)"abcdEfGh", 8);
    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 1)
        result = 1;

    WmThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    WmDestroyCtx(&mpm_ctx);
    return result;
}

int WmTestSearch07 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_WUMANBER);

    WmAddPattern(&mpm_ctx, (u_int8_t *)"abcd", 4, 0, 0);
    WmAddPattern(&mpm_ctx, (u_int8_t *)"eFgH", 4, 1, 1);
    WmPreparePatterns(&mpm_ctx);
    WmThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 2);

    u_int32_t cnt = WmSearch2(&mpm_ctx, &mpm_thread_ctx, (u_int8_t *)"abcdEfGh", 8);
    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 2)
        result = 1;

    WmThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    WmDestroyCtx(&mpm_ctx);
    return result;
}

int WmTestSearch08 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_WUMANBER);

    WmAddPattern(&mpm_ctx, (u_int8_t *)"abcde", 5, 1, 0);
    WmAddPattern(&mpm_ctx, (u_int8_t *)"bcde",  4, 1, 1);
    WmPreparePatterns(&mpm_ctx);
    WmThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 2);

    u_int32_t cnt = WmSearch2(&mpm_ctx, &mpm_thread_ctx, (u_int8_t *)"abcdefgh", 8);
    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 2)
        result = 1;

    WmThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    WmDestroyCtx(&mpm_ctx);
    return result;
}

int WmTestSearch09 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_WUMANBER);

    WmAddPattern(&mpm_ctx, (u_int8_t *)"ab", 2, 1, 0);
    WmPreparePatterns(&mpm_ctx);
    WmThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1);

    u_int32_t cnt = WmSearch2(&mpm_ctx, &mpm_thread_ctx, (u_int8_t *)"ab", 2);
    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 1)
        result = 1;

    WmThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    WmDestroyCtx(&mpm_ctx);
    return result;
}

int WmTestSearch10 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_WUMANBER);

    WmAddPattern(&mpm_ctx, (u_int8_t *)"bc", 2, 1, 0);
    WmAddPattern(&mpm_ctx, (u_int8_t *)"gh", 2, 1, 1);
    WmPreparePatterns(&mpm_ctx);
    WmThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 2);

    u_int32_t cnt = WmSearch2(&mpm_ctx, &mpm_thread_ctx, (u_int8_t *)"abcdefgh", 8);
    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 2)
        result = 1;

    WmThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    WmDestroyCtx(&mpm_ctx);
    return result;
}

int WmTestSearch11 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_WUMANBER);

    WmAddPattern(&mpm_ctx, (u_int8_t *)"a", 1, 1, 0);
    WmAddPattern(&mpm_ctx, (u_int8_t *)"d", 1, 1, 1);
    WmAddPattern(&mpm_ctx, (u_int8_t *)"h", 1, 1, 2);
    WmPreparePatterns(&mpm_ctx);
    WmThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 3);

    u_int32_t cnt = WmSearch1(&mpm_ctx, &mpm_thread_ctx, (u_int8_t *)"abcdefgh", 8);
    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 3)
        result = 1;

    WmThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    WmDestroyCtx(&mpm_ctx);
    return result;
}

int WmTestSearch12 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_WUMANBER);

    WmAddPattern(&mpm_ctx, (u_int8_t *)"A", 1, 1, 0);
    WmAddPattern(&mpm_ctx, (u_int8_t *)"d", 1, 1, 1);
    WmAddPattern(&mpm_ctx, (u_int8_t *)"Z", 1, 1, 2);
    WmPreparePatterns(&mpm_ctx);
    WmThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 3);

    u_int32_t cnt = WmSearch1(&mpm_ctx, &mpm_thread_ctx, (u_int8_t *)"abcdefgh", 8);
    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 2)
        result = 1;

    WmThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    WmDestroyCtx(&mpm_ctx);
    return result;
}

int WmTestSearch13 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_WUMANBER);

    WmAddPattern(&mpm_ctx, (u_int8_t *)"a", 1, 1, 0);
    WmAddPattern(&mpm_ctx, (u_int8_t *)"de",2, 1, 1);
    WmAddPattern(&mpm_ctx, (u_int8_t *)"h", 1, 1, 2);
    WmPreparePatterns(&mpm_ctx);
    WmThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 3);

    u_int32_t cnt = WmSearch1(&mpm_ctx, &mpm_thread_ctx, (u_int8_t *)"abcdefgh", 8);
    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 3)
        result = 1;

    WmThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    WmDestroyCtx(&mpm_ctx);
    return result;
}

int WmTestSearch14 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_WUMANBER);

    WmAddPattern(&mpm_ctx, (u_int8_t *)"A", 1, 1, 0);
    WmAddPattern(&mpm_ctx, (u_int8_t *)"de",2, 1, 1);
    WmAddPattern(&mpm_ctx, (u_int8_t *)"Z", 1, 1, 2);
    WmPreparePatterns(&mpm_ctx);
    WmThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 3);

    u_int32_t cnt = WmSearch1(&mpm_ctx, &mpm_thread_ctx, (u_int8_t *)"abcdefgh", 8);
    MpmMatchCleanup(&mpm_thread_ctx);

    if (cnt == 2)
        result = 1;

    WmThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    WmDestroyCtx(&mpm_ctx);
    return result;
}

int WmTestSearch15 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_WUMANBER);

    WmAddPattern(&mpm_ctx, (u_int8_t *)"A", 1, 1, 0);
    WmAddPattern(&mpm_ctx, (u_int8_t *)"de",2, 1, 1);
    WmAddPattern(&mpm_ctx, (u_int8_t *)"Z", 1, 1, 2);
    WmPreparePatterns(&mpm_ctx);
    WmThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 3);

    WmSearch1(&mpm_ctx, &mpm_thread_ctx, (u_int8_t *)"abcdefgh", 8);

    u_int32_t len = mpm_thread_ctx.match[1].len;

    MpmMatchCleanup(&mpm_thread_ctx);

    if (len == 1)
        result = 1;

    WmThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    WmDestroyCtx(&mpm_ctx);
    return result;
}

int WmTestSearch16 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_WUMANBER);

    WmAddPattern(&mpm_ctx, (u_int8_t *)"A", 1, 1, 0);
    WmAddPattern(&mpm_ctx, (u_int8_t *)"de",2, 1, 1);
    WmAddPattern(&mpm_ctx, (u_int8_t *)"Z", 1, 1, 2);
    WmPreparePatterns(&mpm_ctx);
    WmThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 3);

    WmSearch1(&mpm_ctx, &mpm_thread_ctx, (u_int8_t *)"abcdefgh", 8);

    u_int32_t len = mpm_thread_ctx.match[0].len;

    MpmMatchCleanup(&mpm_thread_ctx);

    if (len == 1)
        result = 1;

    WmThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    WmDestroyCtx(&mpm_ctx);
    return result;
}

int WmTestSearch17 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_WUMANBER);

    WmAddPatternCS(&mpm_ctx, (u_int8_t *)"/VideoAccessCodecInstall.exe", 28, 0);
    WmPreparePatterns(&mpm_ctx);
    WmThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1);

    WmSearch2(&mpm_ctx, &mpm_thread_ctx, (u_int8_t *)"/VideoAccessCodecInstall.exe", 28);

    u_int32_t len = mpm_thread_ctx.match[0].len;

    MpmMatchCleanup(&mpm_thread_ctx);

    if (len == 1)
        result = 1;

    WmThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    WmDestroyCtx(&mpm_ctx);
    return result;
}

int WmTestSearch18 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_WUMANBER);

    WmAddPatternCS(&mpm_ctx, (u_int8_t *)"/VideoAccessCodecInstall.exe", 28, 0);
    WmPreparePatterns(&mpm_ctx);
    WmThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1);

    WmSearch2(&mpm_ctx, &mpm_thread_ctx, (u_int8_t *)"/VideoAccessCodecInstaLL.exe", 28);

    u_int32_t len = mpm_thread_ctx.match[0].len;

    MpmMatchCleanup(&mpm_thread_ctx);

    if (len == 0)
        result = 1;

    WmThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    WmDestroyCtx(&mpm_ctx);
    return result;
}

int WmTestSearch19 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_WUMANBER);

    WmAddPatternCI(&mpm_ctx, (u_int8_t *)"/VideoAccessCodecInstall.exe", 28, 0);
    WmPreparePatterns(&mpm_ctx);
    WmThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1);

    WmSearch2(&mpm_ctx, &mpm_thread_ctx, (u_int8_t *)"/VideoAccessCodecInstaLL.exe", 28);

    u_int32_t len = mpm_thread_ctx.match[0].len;

    MpmMatchCleanup(&mpm_thread_ctx);

    if (len == 1)
        result = 1;

    WmThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    WmDestroyCtx(&mpm_ctx);
    return result;
}

int WmTestSearch20 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_WUMANBER);

    WmAddPatternCS(&mpm_ctx, (u_int8_t *)"/videoaccesscodecinstall.exe", 28, 0);
    WmPreparePatterns(&mpm_ctx);
    WmThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1);

    WmSearch2(&mpm_ctx, &mpm_thread_ctx, (u_int8_t *)"/VideoAccessCodecInstall.exe", 28);

    u_int32_t len = mpm_thread_ctx.match[0].len;

    MpmMatchCleanup(&mpm_thread_ctx);

    if (len == 0)
        result = 1;

    WmThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    WmDestroyCtx(&mpm_ctx);
    return result;
}

int WmTestSearch21 (void) {
    int result = 0;
    MpmCtx mpm_ctx;
    MpmThreadCtx mpm_thread_ctx;
    MpmInitCtx(&mpm_ctx, MPM_WUMANBER);

    WmAddPatternCS(&mpm_ctx, (u_int8_t *)"/videoaccesscodecinstall.exe", 28, 0);
    WmPreparePatterns(&mpm_ctx);
    WmThreadInitCtx(&mpm_ctx, &mpm_thread_ctx, 1);

    WmSearch2(&mpm_ctx, &mpm_thread_ctx, (u_int8_t *)"/videoaccesscodecinstall.exe", 28);

    u_int32_t len = mpm_thread_ctx.match[0].len;

    MpmMatchCleanup(&mpm_thread_ctx);

    if (len == 1)
        result = 1;

    WmThreadDestroyCtx(&mpm_ctx, &mpm_thread_ctx);
    WmDestroyCtx(&mpm_ctx);
    return result;
}

void WmRegisterTests(void) {
    UtRegisterTest("WmTestInitCtx01", WmTestInitCtx01, 1);
    UtRegisterTest("WmTestInitCtx02", WmTestInitCtx02, 1);
    UtRegisterTest("WmTestInitCtx03", WmTestInitCtx03, 1);

    UtRegisterTest("WmTestThreadInitCtx01", WmTestThreadInitCtx01, 1);
    UtRegisterTest("WmTestThreadInitCtx02", WmTestThreadInitCtx02, 1);

    UtRegisterTest("WmTestInitAddPattern01", WmTestInitAddPattern01, 1);
    UtRegisterTest("WmTestInitAddPattern02", WmTestInitAddPattern02, 1);
    UtRegisterTest("WmTestInitAddPattern03", WmTestInitAddPattern03, 1);
    UtRegisterTest("WmTestInitAddPattern04", WmTestInitAddPattern04, 1);
    UtRegisterTest("WmTestInitAddPattern05", WmTestInitAddPattern05, 1);
    UtRegisterTest("WmTestInitAddPattern06", WmTestInitAddPattern06, 1);
    UtRegisterTest("WmTestInitAddPattern07", WmTestInitAddPattern07, 1);

    UtRegisterTest("WmTestPrepare01", WmTestPrepare01, 1);

    UtRegisterTest("WmTestSearch01", WmTestSearch01, 1);
    UtRegisterTest("WmTestSearch02", WmTestSearch02, 1);
    UtRegisterTest("WmTestSearch03", WmTestSearch03, 1);
    UtRegisterTest("WmTestSearch04", WmTestSearch04, 1);
    UtRegisterTest("WmTestSearch05", WmTestSearch05, 1);
    UtRegisterTest("WmTestSearch06", WmTestSearch06, 1);
    UtRegisterTest("WmTestSearch07", WmTestSearch07, 1);
    UtRegisterTest("WmTestSearch08", WmTestSearch08, 1);
    UtRegisterTest("WmTestSearch09", WmTestSearch09, 1);
    UtRegisterTest("WmTestSearch10", WmTestSearch10, 1);
    UtRegisterTest("WmTestSearch11", WmTestSearch11, 1);
    UtRegisterTest("WmTestSearch12", WmTestSearch12, 1);
    UtRegisterTest("WmTestSearch13", WmTestSearch13, 1);
    UtRegisterTest("WmTestSearch14", WmTestSearch14, 1);
    UtRegisterTest("WmTestSearch15", WmTestSearch15, 1);
    UtRegisterTest("WmTestSearch16", WmTestSearch16, 1);
    UtRegisterTest("WmTestSearch17", WmTestSearch17, 1);
    UtRegisterTest("WmTestSearch18", WmTestSearch18, 1);
    UtRegisterTest("WmTestSearch19", WmTestSearch19, 1);
    UtRegisterTest("WmTestSearch20", WmTestSearch20, 1);
    UtRegisterTest("WmTestSearch21", WmTestSearch21, 1);
}


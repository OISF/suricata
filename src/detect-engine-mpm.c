/* Multi pattern matcher */

#include "suricata-common.h"

#include "decode.h"
#include "detect.h"
#include "detect-engine.h"
#include "detect-engine-siggroup.h"
#include "detect-engine-mpm.h"
#include "detect-engine-iponly.h"
#include "util-mpm.h"

#include "flow.h"
#include "flow-var.h"
#include "detect-flow.h"

#include "detect-content.h"
#include "detect-uricontent.h"

#include "util-debug.h"

/** \todo make it possible to use multiple pattern matcher algorithms next to
          eachother. */
//#define PM   MPM_WUMANBER
#define PM   MPM_B2G
//#define PM   MPM_B3G

uint16_t PatternMatchDefaultMatcher(void) {
    return PM;
}

/** \brief Pattern match, scan part -- searches for only 'scan' patterns,
 *         normally one per signature.
 *  \param tv threadvars
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to scan
 */
uint32_t PacketPatternScan(ThreadVars *tv, DetectEngineThreadCtx *det_ctx, Packet *p) {
    uint32_t ret;

    det_ctx->pmq.mode = PMQ_MODE_SCAN;
    ret = mpm_table[det_ctx->sgh->mpm_ctx->mpm_type].Scan(det_ctx->sgh->mpm_ctx, &det_ctx->mtc, &det_ctx->pmq, p->payload, p->payload_len);

    //printf("PacketPatternScan: ret %" PRIu32 "\n", ret);
    return ret;
}

/** \brief Pattern match, search part -- searches for all other patterns
 *  \param tv threadvars
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to scan
 */
uint32_t PacketPatternMatch(ThreadVars *tv, DetectEngineThreadCtx *det_ctx, Packet *p) {
    uint32_t ret;

    det_ctx->pmq.mode = PMQ_MODE_SEARCH;
    ret = mpm_table[det_ctx->sgh->mpm_ctx->mpm_type].Search(det_ctx->sgh->mpm_ctx, &det_ctx->mtc, &det_ctx->pmq, p->payload, p->payload_len);

    //printf("PacketPatternMatch: ret %" PRIu32 "\n", ret);
    return ret;
}

/** \brief cleans up the mpm instance after a match */
void PacketPatternCleanup(ThreadVars *t, DetectEngineThreadCtx *det_ctx) {
    PmqReset(&det_ctx->pmq);

    if (det_ctx->sgh == NULL)
        return;

    /* content */
    if (det_ctx->sgh->mpm_ctx != NULL && mpm_table[det_ctx->sgh->mpm_ctx->mpm_type].Cleanup != NULL) {
        mpm_table[det_ctx->sgh->mpm_ctx->mpm_type].Cleanup(&det_ctx->mtc);
    }
    /* uricontent */
    if (det_ctx->sgh->mpm_uri_ctx != NULL && mpm_table[det_ctx->sgh->mpm_uri_ctx->mpm_type].Cleanup != NULL) {
        mpm_table[det_ctx->sgh->mpm_uri_ctx->mpm_type].Cleanup(&det_ctx->mtcu);
    }
}

void PatternMatchDestroy(MpmCtx *mpm_ctx, uint16_t mpm_matcher) {
    SCLogDebug("mpm_ctx %p, mpm_matcher %"PRIu16"", mpm_ctx, mpm_matcher);
    mpm_table[mpm_matcher].DestroyCtx(mpm_ctx);
}

void PatternMatchPrepare(MpmCtx *mpm_ctx, uint16_t mpm_matcher) {
    SCLogDebug("mpm_ctx %p, mpm_matcher %"PRIu16"", mpm_ctx, mpm_matcher);
    MpmInitCtx(mpm_ctx, mpm_matcher);
}

void PatternMatchThreadPrint(MpmThreadCtx *mpm_thread_ctx, uint16_t mpm_matcher) {
    SCLogDebug("mpm_thread_ctx %p, mpm_matcher %"PRIu16" defunct", mpm_thread_ctx, mpm_matcher);
    //mpm_table[mpm_matcher].PrintThreadCtx(mpm_thread_ctx);
}
void PatternMatchThreadDestroy(MpmThreadCtx *mpm_thread_ctx, uint16_t mpm_matcher) {
    SCLogDebug("mpm_thread_ctx %p, mpm_matcher %"PRIu16"", mpm_thread_ctx, mpm_matcher);
    mpm_table[mpm_matcher].DestroyThreadCtx(NULL, mpm_thread_ctx);
}
void PatternMatchThreadPrepare(MpmThreadCtx *mpm_thread_ctx, uint16_t mpm_matcher, uint32_t max_id) {
    SCLogDebug("mpm_thread_ctx %p, type %"PRIu16", max_id %"PRIu32"", mpm_thread_ctx, mpm_matcher, max_id);
    MpmInitThreadCtx(mpm_thread_ctx, mpm_matcher, max_id);
}


/* free the pattern matcher part of a SigGroupHead */
void PatternMatchDestroyGroup(SigGroupHead *sh) {
    /* content */
    if (sh->flags & SIG_GROUP_HAVECONTENT && sh->mpm_ctx != NULL &&
        !(sh->flags & SIG_GROUP_HEAD_MPM_COPY)) {
        SCLogDebug("destroying mpm_ctx %p (sh %p)", sh->mpm_ctx, sh);
        mpm_table[sh->mpm_ctx->mpm_type].DestroyCtx(sh->mpm_ctx);
        free(sh->mpm_ctx);

        /* ready for reuse */
        sh->mpm_ctx = NULL;
        sh->flags &= ~SIG_GROUP_HAVECONTENT;
    }

    /* uricontent */
    if (sh->flags & SIG_GROUP_HAVEURICONTENT && sh->mpm_uri_ctx != NULL &&
        !(sh->flags & SIG_GROUP_HEAD_MPM_URI_COPY)) {
        SCLogDebug("destroying mpm_uri_ctx %p (sh %p)", sh->mpm_uri_ctx, sh);
        mpm_table[sh->mpm_uri_ctx->mpm_type].DestroyCtx(sh->mpm_uri_ctx);
        free(sh->mpm_uri_ctx);

        /* ready for reuse */
        sh->mpm_uri_ctx = NULL;
        sh->flags &= ~SIG_GROUP_HAVEURICONTENT;
    }
}

static int g_uricontent_scan = 0;
static int g_uricontent_search = 0;
static int g_content_maxdepth = 0;
static int g_content_minoffset = 0;
static int g_content_total = 0;

static int g_content_maxlen = 0;
static int g_content_sigcnt = 0;
static int g_content_sigcnt1 = 0;
static int g_content_sigcnt2 = 0;
static int g_content_sigcnt3 = 0;
static int g_content_sigcnt4 = 0;
static int g_content_sigcnt5 = 0;
static int g_content_sigcnt10= 0;

void DbgPrintScanSearchStats() {
#if 0
    printf(" - MPM: scan %" PRId32 ", search %" PRId32 " (%02.1f%%) :\n", g_content_scan, g_content_search,
        (float)(g_content_scan/(float)(g_content_scan+g_content_search))*100);
    printf(" - MPM: maxdepth %" PRId32 ", total %" PRId32 " (%02.1f%%) :\n", g_content_maxdepth, g_content_total,
        (float)(g_content_maxdepth/(float)(g_content_total))*100);
    printf(" - MPM: minoffset %" PRId32 ", total %" PRId32 " (%02.1f%%) :\n", g_content_minoffset, g_content_total,
        (float)(g_content_minoffset/(float)(g_content_total))*100);
    printf(" - MPM: avg maxlen %02.1f (%" PRIu32 "/%" PRIu32 ")\n", (float)((float)g_content_maxlen/(float)(g_content_sigcnt)), g_content_maxlen, g_content_sigcnt);
    printf(" - MPM: 1 len %" PRIu32 " (%02.1f%%)\n", g_content_sigcnt1, (float)(g_content_sigcnt1/(float)(g_content_sigcnt))*100);
    printf(" - MPM: 2 len %" PRIu32 " (%02.1f%%)\n", g_content_sigcnt2, (float)(g_content_sigcnt2/(float)(g_content_sigcnt))*100);
    printf(" - MPM: 3 len %" PRIu32 " (%02.1f%%)\n", g_content_sigcnt3, (float)(g_content_sigcnt3/(float)(g_content_sigcnt))*100);
    printf(" - MPM: 4 len %" PRIu32 " (%02.1f%%)\n", g_content_sigcnt4, (float)(g_content_sigcnt4/(float)(g_content_sigcnt))*100);
    printf(" - MPM: 5+len %" PRIu32 " (%02.1f%%)\n", g_content_sigcnt5, (float)(g_content_sigcnt5/(float)(g_content_sigcnt))*100);
    printf(" - MPM: 10+ln %" PRIu32 " (%02.1f%%)\n", g_content_sigcnt10,(float)(g_content_sigcnt10/(float)(g_content_sigcnt))*100);
#endif
}

/** \brief Hash for looking up contents that are most used,
 *         always used, etc. */
typedef struct ContentHash_ {
    DetectContentData *ptr;
    uint16_t cnt;
    uint8_t use; /* use no matter what */
    uint8_t nosearch; /* single match, no search after
                        * scan match (for this pattern) */
} ContentHash;

uint32_t ContentHashFunc(HashTable *ht, void *data, uint16_t datalen) {
     ContentHash *ch = (ContentHash *)data;
     DetectContentData *co = ch->ptr;
     uint32_t hash = 0;
     int i;
     for (i = 0; i < co->content_len; i++) {
         hash += co->content[i];
     }
     hash = hash % ht->array_size;
//printf("hash %" PRIu32 "\n", hash);
     return hash;
}

char ContentHashCompareFunc(void *data1, uint16_t len1, void *data2, uint16_t len2) {
    ContentHash *ch1 = (ContentHash *)data1;
    ContentHash *ch2 = (ContentHash *)data2;
    DetectContentData *co1 = ch1->ptr;
    DetectContentData *co2 = ch2->ptr;

    if (co1->content_len == co2->content_len &&
        memcmp(co1->content, co2->content, co1->content_len) == 0)
        return 1;

    return 0;
}

ContentHash *ContentHashAlloc(DetectContentData *ptr) {
    ContentHash *ch = malloc(sizeof(ContentHash));
    if (ch == NULL)
        return NULL;

    ch->ptr = ptr;
    ch->cnt = 1;
    ch->use = 0;
    ch->nosearch = 0;

    return ch;
}

void ContentHashFree(void *ch) {
    free(ch);
}

/** \brief Predict a strength value for patterns
 *
 * Patterns with high character diversity score higher.
 * Alpha chars score not so high
 * Other printable + a few common codes a little higher
 * Everything else highest.
 * Longer patterns score better than short patters.
 */
uint32_t PatternStrength(uint8_t *pat, uint16_t patlen, uint16_t len) {
    uint8_t a[256];
    memset(&a,0,sizeof(a));

    uint32_t s = 0;
    uint16_t u = 0;
    for (u = 0; u < patlen; u++) {
        if (a[pat[u]] == 0) {
            if (isalpha(pat[u]))
                s+=3;
            else if (isprint(pat[u]) || pat[u] == 0x00 || pat[u] == 0x01 || pat[u] == 0xFF)
                s+=4;
            else
                s+=6;//5

            a[pat[u]] = 1;
        } else {
            s++;
        }
    }

    return s;
}

/** \brief Setup the content portion of the sig group head */
static int PatternMatchPreprarePopulateMpm(DetectEngineCtx *de_ctx, SigGroupHead *sgh) {
    uint32_t sig;
    uint32_t *fast_pattern = NULL;

    fast_pattern = (uint32_t *)malloc(sgh->sig_cnt * sizeof(uint32_t));
    if (fast_pattern == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        return -1;
    }
    memset(fast_pattern, 0, sgh->sig_cnt * sizeof(uint32_t));

    HashTable *ht = HashTableInit(4096, ContentHashFunc, ContentHashCompareFunc, ContentHashFree);
    if (ht == NULL)
        return -1;

    /* add all the contents to a counting hash */
    for (sig = 0; sig < sgh->sig_cnt; sig++) {
        uint32_t num = sgh->match_array[sig];

        Signature *s = de_ctx->sig_array[num];
        if (s == NULL)
            continue;

        int cnt = 0;
        SigMatch *sm;
        /* get the total no of patterns in this Signature, as well as find out
         * if we have a fast_pattern set in this Signature */
        for (sm = s->match; sm != NULL; sm = sm->next) {
            if (sm->type == DETECT_CONTENT) {
                DetectContentData *co = (DetectContentData *)sm->ctx;
                if (co == NULL)
                    continue;

                if (co->flags & DETECT_CONTENT_FAST_PATTERN) {
                    fast_pattern[sig] = 1;

                    ContentHash *ch = ContentHashAlloc(co);
                    if (ch == NULL)
                        goto error;

                    ContentHash *lookup_ch = (ContentHash *)HashTableLookup(ht, ch, 0);
                    if (lookup_ch == NULL) {
                        if (HashTableAdd(ht, ch, 0) < 0)
                            printf("Add hash failed\n");
                    } else {
                        /* only set the nosearch flag if all sigs have it
                         * as their sole pattern */
                        if (ch->nosearch == 0)
                            lookup_ch->nosearch = 0;

                        lookup_ch->cnt++;
                        ContentHashFree(ch);
                    }
                }
                cnt++;
            }
        }

        if (fast_pattern[sig] == 1) {
            if (cnt == 1) {
                ContentHash *ch = ContentHashAlloc(s->match->ctx);
                ch->nosearch = 1;
                ch->use = 1;
            }
            continue;
        }

        for (sm = s->match; sm != NULL; sm = sm->next) {
            if (sm->type == DETECT_CONTENT) {
                DetectContentData *co = (DetectContentData *)sm->ctx;
                if (co == NULL)
                    continue;

                if (co->content_len < sgh->mpm_content_maxlen) {
                    continue;
                }

                ContentHash *ch = ContentHashAlloc(co);
                if (ch == NULL)
                    goto error;

                if (cnt == 1) {
                    SCLogDebug("sig has just one pattern, so we know we will use it in the scan phase and no searching will be necessary.");
                    ch->nosearch = 1;
                    ch->use = 1;
                }

                ContentHash *lookup_ch = (ContentHash *)HashTableLookup(ht, ch, 0);
                if (lookup_ch == NULL) {
                    int r = HashTableAdd(ht, ch, 0);
                    if (r < 0) printf("Add hash failed\n");
                } else {
                    /* at least one sig relies soly on this content
                     * so flag that we will use this content no matter
                     * what. */
                    if (cnt == 1) {
                        lookup_ch->use = 1;
                    }

                    /* only set the nosearch flag if all sigs have it
                     * as their sole pattern */
                    if (ch->nosearch == 0)
                        lookup_ch->nosearch = 0;

                    lookup_ch->cnt++;
                    ContentHashFree(ch);
                }
            }
        }
    }

    /* now determine which one to add to the scan phase */
    for (sig = 0; sig < sgh->sig_cnt; sig++) {
        uint32_t num = sgh->match_array[sig];

        Signature *s = de_ctx->sig_array[num];
        if (s == NULL)
            continue;

        ContentHash *scan_ch = NULL;
        SigMatch *sm = s->match;
        for ( ; sm != NULL; sm = sm->next) {

            if (sm->type == DETECT_CONTENT) {
                DetectContentData *co = (DetectContentData *)sm->ctx;
                if (co == NULL)
                    continue;

                if (fast_pattern[sig] == 1) {
                    if (!(co->flags & DETECT_CONTENT_FAST_PATTERN))
                        continue;
                } else if (co->content_len < sgh->mpm_content_maxlen) {
                    continue;
                }

                ContentHash *ch = ContentHashAlloc(co);
                if (ch == NULL)
                    goto error;

                ContentHash *lookup_ch = (ContentHash *)HashTableLookup(ht, ch, 0);
                if (lookup_ch == NULL) {
                    continue;
                }

                SCLogDebug("lookup_ch->use %u, cnt %u", lookup_ch->use, lookup_ch->cnt);

                if (scan_ch == NULL) {
                    SCLogDebug("scan_ch == NULL, so selecting lookup_ch->ptr->id %"PRIu32"", lookup_ch->ptr->id);
                    scan_ch = lookup_ch;
                } else {
                    if (lookup_ch->use == 0) {
                        uint32_t ls = PatternStrength(lookup_ch->ptr->content,lookup_ch->ptr->content_len,sgh->mpm_content_maxlen);
                        uint32_t ss = PatternStrength(scan_ch->ptr->content,scan_ch->ptr->content_len,sgh->mpm_content_maxlen);
                        if (ls > ss) {
                            SCLogDebug("lookup_ch->ptr->id %"PRIu32" selected over %"PRIu32"", lookup_ch->ptr->id, scan_ch->ptr->id);
                            scan_ch = lookup_ch;
                        }
                        else if (ls == ss) {
                            /* if 2 patterns are of equal strength, we pick the longest */
                            if (lookup_ch->ptr->content_len > scan_ch->ptr->content_len) {
                                SCLogDebug("lookup_ch->ptr->id %"PRIu32" selected over %"PRIu32" as the first is longer", lookup_ch->ptr->id, scan_ch->ptr->id);
                                scan_ch = lookup_ch;
                            }
                        } else {
                            SCLogDebug("sticking with scan_ch");
                        }
                    } else {
                        if (scan_ch->use == 0)
                            scan_ch = lookup_ch;
                        else {
                            uint32_t ls = PatternStrength(lookup_ch->ptr->content,lookup_ch->ptr->content_len,sgh->mpm_content_maxlen);
                            uint32_t ss = PatternStrength(scan_ch->ptr->content,scan_ch->ptr->content_len,sgh->mpm_content_maxlen);
                            if (ls > ss) {
                                SCLogDebug("lookup_ch->ptr->id %"PRIu32" selected over %"PRIu32"", lookup_ch->ptr->id, scan_ch->ptr->id);
                                scan_ch = lookup_ch;
                            }
                            /* if 2 patterns are of equal strength, we pick the longest */
                            else if (ls == ss) {
                                if (lookup_ch->ptr->content_len > scan_ch->ptr->content_len) {
                                    SCLogDebug("lookup_ch->ptr->id %"PRIu32" selected over %"PRIu32" as the first is longer", lookup_ch->ptr->id, scan_ch->ptr->id);
                                    scan_ch = lookup_ch;
                                }
                            }
                        }
                    }
                }

                ContentHashFree(ch);
            }
        }
        /* now add the scan_ch to the mpm ctx */
        if (scan_ch != NULL) {
            DetectContentData *co = scan_ch->ptr;
            uint16_t offset = s->flags & SIG_FLAG_RECURSIVE ? 0 : co->offset;
            uint16_t depth = s->flags & SIG_FLAG_RECURSIVE ? 0 : co->depth;
            offset = scan_ch->cnt ? 0 : offset;
            depth = scan_ch->cnt ? 0 : depth;

            if (co->flags & DETECT_CONTENT_NOCASE) {
                mpm_table[sgh->mpm_ctx->mpm_type].AddScanPatternNocase(sgh->mpm_ctx, co->content, co->content_len, offset, depth, co->id, s->num, scan_ch->nosearch);
            } else {
                mpm_table[sgh->mpm_ctx->mpm_type].AddScanPattern(sgh->mpm_ctx, co->content, co->content_len, offset, depth, co->id, s->num, scan_ch->nosearch);
            }

            SCLogDebug("%"PRIu32" adding co->id %"PRIu32" to the scan phase (s->num %"PRIu32")", s->id, co->id, s->num);
        } else {
            SCLogDebug("%"PRIu32" no scan pattern selected", s->id);
        }
        /* add the rest of the patterns to the search ctx */
        for (sm = s->match ; sm != NULL; sm = sm->next) {
            if (sm->type == DETECT_CONTENT) {
                DetectContentData *co = (DetectContentData *)sm->ctx;
                if (co == NULL)
                    continue;

                /* skip the one we already added */
                if (scan_ch != NULL && co == scan_ch->ptr) {
                    SCLogDebug("%"PRIu32" co->id %"PRIu32" not added to search, already in scan", s->id, co->id);
                    continue;
                }

                uint16_t offset = s->flags & SIG_FLAG_RECURSIVE ? 0 : co->offset;
                uint16_t depth = s->flags & SIG_FLAG_RECURSIVE ? 0 : co->depth;

                if (co->flags & DETECT_CONTENT_NOCASE) {
                    mpm_table[sgh->mpm_ctx->mpm_type].AddPatternNocase(sgh->mpm_ctx, co->content, co->content_len, offset, depth, co->id, s->num);
                } else {
                    mpm_table[sgh->mpm_ctx->mpm_type].AddPattern(sgh->mpm_ctx, co->content, co->content_len, offset, depth, co->id, s->num);
                }

                SCLogDebug("%"PRIu32" adding co->id %"PRIu32" to the search phase", s->id, co->id);
            }
        }
    }

    if (fast_pattern != NULL)
        free(fast_pattern);
    HashTableFree(ht);
    return 0;
error:
    if (fast_pattern != NULL)
        free(fast_pattern);
    if (ht != NULL)
        HashTableFree(ht);
    return -1;
}

/** \brief Prepare the pattern matcher ctx in a sig group head.
 *
 *  \todo determine if a content match can set the 'single' flag
 *  \todo do error checking
 *  \todo rewrite the COPY stuff
 */
int PatternMatchPrepareGroup(DetectEngineCtx *de_ctx, SigGroupHead *sh)
{
    Signature *s = NULL;
    SigMatch *sm = NULL;
    uint32_t co_cnt = 0;
    uint32_t ur_cnt = 0;
    uint32_t cnt = 0;
    uint32_t sig = 0;

    g_content_sigcnt++;

    if (!(sh->flags & SIG_GROUP_HEAD_MPM_COPY))
        sh->mpm_content_maxlen = 0;

    if (!(sh->flags & SIG_GROUP_HEAD_MPM_URI_COPY))
        sh->mpm_uricontent_maxlen = 0;

    /** see if this head has content and/or uricontent
     *  \todo we can move this to the signature init phase */
    for (sig = 0; sig < sh->sig_cnt; sig++) {
        uint32_t num = sh->match_array[sig];

        s = de_ctx->sig_array[num];
        if (s == NULL)
            continue;

        /* find flow setting of this rule */
        for (sm = s->match; sm != NULL; sm = sm->next) {
            if (sm->type == DETECT_CONTENT) {
                co_cnt++;
                s->flags |= SIG_FLAG_MPM;
            } else if (sm->type == DETECT_URICONTENT) {
                ur_cnt++;
                s->flags |= SIG_FLAG_MPM;
            }
        }
    }

    if (co_cnt > 0) {
        sh->flags |= SIG_GROUP_HAVECONTENT;
    }
    if (ur_cnt > 0) {
        sh->flags |= SIG_GROUP_HAVEURICONTENT;
    }

    /* intialize contexes */
    if (sh->flags & SIG_GROUP_HAVECONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_COPY)) {
        /* search */
        sh->mpm_ctx = malloc(sizeof(MpmCtx));
        if (sh->mpm_ctx == NULL)
            goto error;

        memset(sh->mpm_ctx, 0x00, sizeof(MpmCtx));
        MpmInitCtx(sh->mpm_ctx, de_ctx->mpm_matcher);
    }
    if (sh->flags & SIG_GROUP_HAVEURICONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_URI_COPY)) {
        sh->mpm_uri_ctx = malloc(sizeof(MpmCtx));
        if (sh->mpm_uri_ctx == NULL)
            goto error;

        memset(sh->mpm_uri_ctx, 0x00, sizeof(MpmCtx));
        MpmInitCtx(sh->mpm_uri_ctx, de_ctx->mpm_matcher);
    }

    uint32_t mpm_content_cnt = 0, mpm_uricontent_cnt = 0;
    uint16_t mpm_content_maxdepth = 65535, mpm_content_minoffset = 65535;
    uint16_t mpm_content_maxdepth_one = 65535, mpm_content_minoffset_one = 65535;
    int mpm_content_depth_present = -1;
    int mpm_content_offset_present = -1;

    /* for each signature in this group do */
    for (sig = 0; sig < sh->sig_cnt; sig++) {
        uint32_t num = sh->match_array[sig];

        s = de_ctx->sig_array[num];
        if (s == NULL)
            continue;

        cnt++;

        char content_added = 0;
        uint16_t content_maxlen = 0, uricontent_maxlen = 0;
        uint16_t content_minlen = 0, uricontent_minlen = 0;
        uint16_t content_cnt = 0, uricontent_cnt = 0;
        uint16_t content_maxdepth = 65535;
        uint16_t content_maxdepth_one = 65535;
        uint16_t content_minoffset = 65535;
        uint16_t content_minoffset_one = 65535;
        SigMatch *sm;

        /* determine the length of the longest pattern */
        for (sm = s->match; sm != NULL; sm = sm->next) {
            if (sm->type == DETECT_CONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_COPY)) {
                DetectContentData *cd = (DetectContentData *)sm->ctx;

                if (cd->content_len > content_maxlen)
                    content_maxlen = cd->content_len;

                if (content_minlen == 0) content_minlen = cd->content_len;
                else if (cd->content_len < content_minlen)
                    content_minlen = cd->content_len;

                mpm_content_cnt++;
                content_cnt++;

                if (!content_added) {
                    content_added = 1;
                }
            } else if (sm->type == DETECT_URICONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_URI_COPY)) {
                DetectUricontentData *ud = (DetectUricontentData *)sm->ctx;
                if (ud->uricontent_len > uricontent_maxlen)
                    uricontent_maxlen = ud->uricontent_len;

                if (uricontent_minlen == 0) uricontent_minlen = ud->uricontent_len;
                else if (ud->uricontent_len < uricontent_minlen)
                    uricontent_minlen = ud->uricontent_len;

                mpm_uricontent_cnt++;
                uricontent_cnt++;
            }
        }

        /* determine the min offset and max depth of the longest pattern(s) */
        for (sm = s->match; sm != NULL; sm = sm->next) {
            if (sm->type == DETECT_CONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_COPY)) {
                DetectContentData *cd = (DetectContentData *)sm->ctx;
                //if (content_maxlen < 4) {
                //printf("\""); PrintRawUriFp(stdout,cd->content,cd->content_len); printf("\" ");
                //}
                if (cd->content_len == content_maxlen) {
                    if (content_maxdepth > cd->depth)
                        content_maxdepth = cd->depth;

                    if (content_minoffset > cd->offset)
                        content_minoffset = cd->offset;
                }
            } else if (sm->type == DETECT_URICONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_URI_COPY)) {
                DetectUricontentData *ud = (DetectUricontentData *)sm->ctx;
                if (ud->uricontent_len == uricontent_maxlen) {
                    /** \todo we don't support offset in uricontent */
                }
            }
        }
        //if (content_maxlen < 4 && content_cnt) printf(" (%" PRIu32 ", min %" PRIu32 ", max %" PRIu32 ")\n", content_cnt, content_minlen, content_maxlen);

        int content_depth_atleastone = 0;
        int content_offset_atleastone = 0;
        /* determine if we have at least one pattern with a depth */
        for (sm = s->match; sm != NULL; sm = sm->next) {
            if (sm->type == DETECT_CONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_COPY)) {
                DetectContentData *cd = (DetectContentData *)sm->ctx;
                if (cd->depth) {
                    content_depth_atleastone = 1;

                    if (content_maxdepth_one > cd->depth)
                        content_maxdepth_one = cd->depth;
                }
                if (cd->offset) {
                    content_offset_atleastone = 1;

                    if (content_minoffset_one > cd->offset)
                        content_minoffset_one = cd->offset;
                }
            }
        }

        if (mpm_content_depth_present == -1) mpm_content_depth_present = content_depth_atleastone;
        else if (content_depth_atleastone == 0) {
            mpm_content_depth_present = 0;
        }

        if (mpm_content_offset_present == -1) mpm_content_offset_present = content_offset_atleastone;
        else if (content_offset_atleastone == 0) {
            mpm_content_offset_present = 0;
        }

        if (content_maxdepth == 65535)
            content_maxdepth = 0;
        if (content_maxdepth_one == 65535)
            content_maxdepth_one = 0;
        if (content_minoffset == 65535)
            content_minoffset = 0;
        if (content_minoffset_one == 65535)
            content_minoffset_one = 0;

        if (content_maxdepth != 0) {
            //printf("content_maxdepth %" PRIu32 " (sid %" PRIu32 ")\n", content_maxdepth, s->id);
        }
        if (content_minoffset != 0) {
            //printf("content_minoffset %" PRIu32 " (sid %" PRIu32 ")\n", content_minoffset, s->id);
        }

        if (mpm_content_maxdepth > content_maxdepth)
            mpm_content_maxdepth = content_maxdepth;
        if (mpm_content_maxdepth_one > content_maxdepth_one)
            mpm_content_maxdepth_one = content_maxdepth_one;
        if (mpm_content_minoffset > content_minoffset)
            mpm_content_minoffset = content_minoffset;
        if (mpm_content_minoffset_one > content_minoffset_one)
            mpm_content_minoffset_one = content_minoffset_one;

        if (content_cnt) {
            if (sh->mpm_content_maxlen == 0) sh->mpm_content_maxlen = content_maxlen;
            if (sh->mpm_content_maxlen > content_maxlen)
                sh->mpm_content_maxlen = content_maxlen;
        }
        if (uricontent_cnt) {
            if (sh->mpm_uricontent_maxlen == 0) sh->mpm_uricontent_maxlen = uricontent_maxlen;
            if (sh->mpm_uricontent_maxlen > uricontent_maxlen)
                sh->mpm_uricontent_maxlen = uricontent_maxlen;
        }
    }

    g_content_maxlen += sh->mpm_content_maxlen;
    if (sh->mpm_content_maxlen == 1) g_content_sigcnt1++;
    if (sh->mpm_content_maxlen == 2) g_content_sigcnt2++;
    if (sh->mpm_content_maxlen == 3) g_content_sigcnt3++;
    if (sh->mpm_content_maxlen == 4) g_content_sigcnt4++;
    if (sh->mpm_content_maxlen >= 5) g_content_sigcnt5++;
    if (sh->mpm_content_maxlen >= 10) g_content_sigcnt10++;

    /* add the patterns for uricontent signatures */
    for (sig = 0; sig < sh->sig_cnt; sig++) {
        uint32_t num = sh->match_array[sig];

        s = de_ctx->sig_array[num];
        if (s == NULL)
            continue;

        uint16_t content_maxlen = 0, uricontent_maxlen = 0;
        uint16_t content_minlen = 0, uricontent_minlen = 0;

        /* determine the length of the longest pattern */
        for (sm = s->match; sm != NULL; sm = sm->next) {
            if (sm->type == DETECT_CONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_COPY)) {
                DetectContentData *cd = (DetectContentData *)sm->ctx;

                if (cd->content_len > content_maxlen)
                    content_maxlen = cd->content_len;

                if (content_minlen == 0) content_minlen = cd->content_len;
                else if (cd->content_len < content_minlen)
                    content_minlen = cd->content_len;
            } else if (sm->type == DETECT_URICONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_URI_COPY)) {
                DetectUricontentData *ud = (DetectUricontentData *)sm->ctx;
                if (ud->uricontent_len > uricontent_maxlen)
                    uricontent_maxlen = ud->uricontent_len;

                if (uricontent_minlen == 0) uricontent_minlen = ud->uricontent_len;
                else if (ud->uricontent_len < uricontent_minlen)
                    uricontent_minlen = ud->uricontent_len;
            }
        }
        char uricontent_scanadded = 0;
        for (sm = s->match; sm != NULL; sm = sm->next) {
            if (sm->type == DETECT_URICONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_URI_COPY)) {
                DetectUricontentData *ud = (DetectUricontentData *)sm->ctx;

                /* only add the pattern if: we didn't add a pattern already,
                 * length is the same as maxlen (ie we only add the longest pattern) */
                if (!uricontent_scanadded && uricontent_maxlen == ud->uricontent_len) {
                    if (ud->flags & DETECT_URICONTENT_NOCASE) {
                        mpm_table[sh->mpm_uri_ctx->mpm_type].AddScanPatternNocase(sh->mpm_uri_ctx, ud->uricontent, ud->uricontent_len, 0, 0, ud->id, s->num, 0);
                    } else {
                        mpm_table[sh->mpm_uri_ctx->mpm_type].AddScanPattern(sh->mpm_uri_ctx, ud->uricontent, ud->uricontent_len, 0, 0, ud->id, s->num, 0);
                    }
                    uricontent_scanadded = 1;

                /* otherwise it's a 'search' pattern */
                } else {
                    if (ud->flags & DETECT_URICONTENT_NOCASE) {
                        mpm_table[sh->mpm_uri_ctx->mpm_type].AddPatternNocase(sh->mpm_uri_ctx, ud->uricontent, ud->uricontent_len, 0, 0, ud->id, s->num);
                    } else {
                        mpm_table[sh->mpm_uri_ctx->mpm_type].AddPattern(sh->mpm_uri_ctx, ud->uricontent, ud->uricontent_len, 0, 0, ud->id, s->num);
                    }
                }
            }
        }
    }

    /* content */
    if (sh->flags & SIG_GROUP_HAVECONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_COPY)) {
        /* load the patterns */
        PatternMatchPreprarePopulateMpm(de_ctx, sh);

        if (mpm_table[sh->mpm_ctx->mpm_type].Prepare != NULL) {
            mpm_table[sh->mpm_ctx->mpm_type].Prepare(sh->mpm_ctx);
        }

        if (mpm_content_maxdepth) {
            // printf("mpm_content_maxdepth %" PRIu32 "\n", mpm_content_maxdepth);
            g_content_maxdepth++;
        }
        if (mpm_content_minoffset) {
            // printf("mpm_content_minoffset %" PRIu32 "\n", mpm_content_minoffset);
            g_content_minoffset++;
        }
        g_content_total++;

        //if (mpm_content_depth_present) printf("(sh %p) at least one depth: %" PRId32 ", depth %" PRIu32 "\n", sh, mpm_content_depth_present, mpm_content_maxdepth_one);
        //if (mpm_content_offset_present) printf("(sh %p) at least one offset: %" PRId32 ", offset %" PRIu32 "\n", sh, mpm_content_offset_present, mpm_content_minoffset_one);
        //sh->mpm_ctx->PrintCtx(sh->mpm_ctx);
    }

    /* uricontent */
    if (sh->flags & SIG_GROUP_HAVEURICONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_URI_COPY)) {
        if (mpm_table[sh->mpm_uri_ctx->mpm_type].Prepare != NULL) {
            mpm_table[sh->mpm_uri_ctx->mpm_type].Prepare(sh->mpm_uri_ctx);
        }
        if (mpm_uricontent_cnt && sh->mpm_uricontent_maxlen > 1) {
            // printf("mpm_uricontent_cnt %" PRIu32 ", mpm_uricontent_maxlen %" PRId32 "\n", mpm_uricontent_cnt, mpm_uricontent_maxlen);
            g_uricontent_scan++;
        } else {
            g_uricontent_search++;
        }

        //sh->mpm_uri_ctx->PrintCtx(sh->mpm_uri_ctx);
    }

    return 0;
error:
    /* XXX */
    return -1;
}


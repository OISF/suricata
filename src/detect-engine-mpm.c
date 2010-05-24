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
 * Multi pattern matcher
 */

#include "suricata.h"
#include "suricata-common.h"

#include "decode.h"
#include "detect.h"
#include "detect-engine.h"
#include "detect-engine-siggroup.h"
#include "detect-engine-mpm.h"
#include "detect-engine-iponly.h"
#include "util-mpm.h"
#include "conf.h"

#include "flow.h"
#include "flow-var.h"
#include "detect-flow.h"

#include "detect-content.h"
#include "detect-uricontent.h"
#include "util-cuda-handlers.h"
#include "util-mpm-b2g-cuda.h"

#include "util-enum.h"
#include "util-debug.h"

/** \todo make it possible to use multiple pattern matcher algorithms next to
          eachother. */
//#define PM   MPM_WUMANBER
//#define PM   MPM_B2G
#ifdef __SC_CUDA_SUPPORT__
#define PM   MPM_B2G_CUDA
#else
#define PM   MPM_B2G
#endif
//#define PM   MPM_B3G

/* holds the string-enum mapping for the enums that define the different MPM
 * algos in util-mpm.h */
SCEnumCharMap sc_mpm_algo_map[] = {
    { "b2g",      MPM_B2G },
    { "b3g",      MPM_B3G },
    { "wumanber", MPM_WUMANBER },
#ifdef __SC_CUDA_SUPPORT__
    { "b2g_cuda", MPM_B2G_CUDA },
#endif
};


/** \brief  Function to return the default multi pattern matcher algorithm to be
 *          used by the engine
 *  \retval mpm algo value
 */
uint16_t PatternMatchDefaultMatcher(void) {
    char *mpm_algo;
    int mpm_algo_val = PM;

    /* Get the mpm algo defined in config file by the user */
    if ((ConfGet("mpm-algo", &mpm_algo)) == 1) {
        mpm_algo_val = SCMapEnumNameToValue(mpm_algo, sc_mpm_algo_map);
        if (mpm_algo_val == -1) {
            SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY, "Invalid mpm algo supplied "
                       "in the yaml conf file: \"%s\"", mpm_algo);
            exit(EXIT_FAILURE);
        }
    }

    return mpm_algo_val;
}

/** \brief Pattern match -- searches for only one pattern per signature.
 *
 *  \param tv threadvars
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *
 *  \retval ret number of matches
 */
uint32_t PacketPatternSearch(ThreadVars *tv, DetectEngineThreadCtx *det_ctx,
                           Packet *p)
{
    SCEnter();

    uint32_t ret;
#ifndef __SC_CUDA_SUPPORT__
    ret = mpm_table[det_ctx->sgh->mpm_ctx->mpm_type].Search(det_ctx->sgh->mpm_ctx,
                                                          &det_ctx->mtc,
                                                          &det_ctx->pmq,
                                                          p->payload,
                                                          p->payload_len);
#else
    /* if the user has enabled cuda support, but is not using the cuda mpm
     * algo, then we shouldn't take the path of the dispatcher.  Call the mpm
     * directly */
    if (det_ctx->sgh->mpm_ctx->mpm_type != MPM_B2G_CUDA) {
        ret = mpm_table[det_ctx->sgh->mpm_ctx->mpm_type].Search(det_ctx->sgh->mpm_ctx,
                                                              &det_ctx->mtc,
                                                              &det_ctx->pmq,
                                                              p->payload,
                                                              p->payload_len);
        SCReturnInt(ret);
    }

    SCCudaHlProcessPacketWithDispatcher(p, det_ctx, &ret);
#endif

    SCReturnInt(ret);
}

/** \brief Uri Pattern match -- searches for one pattern per signature.
 *
 *  \param tv threadvars
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *
 *  \retval ret number of matches
 */
uint32_t UriPatternSearch(ThreadVars *tv, DetectEngineThreadCtx *det_ctx,
                        uint8_t *uri, uint16_t uri_len)
{
    SCEnter();

    if (det_ctx->sgh->mpm_uri_ctx == NULL)
        SCReturnUInt(0U);

    uint32_t ret;
#ifndef __SC_CUDA_SUPPORT__
    ret = mpm_table[det_ctx->sgh->mpm_uri_ctx->mpm_type].Search
        (det_ctx->sgh->mpm_uri_ctx, &det_ctx->mtcu, &det_ctx->pmq,
         uri, uri_len);
#else
    /* if the user has enabled cuda support, but is not using the cuda mpm
     * algo, then we shouldn't take the path of the dispatcher.  Call the mpm
     * directly */
    if (det_ctx->sgh->mpm_uri_ctx->mpm_type != MPM_B2G_CUDA) {
        ret = mpm_table[det_ctx->sgh->mpm_uri_ctx->mpm_type].Search
            (det_ctx->sgh->mpm_uri_ctx, &det_ctx->mtcu, &det_ctx->pmq,
             uri, uri_len);
        SCReturnUInt(ret);
    }

    SCCudaHlProcessUriWithDispatcher(uri, uri_len, det_ctx, &ret);
#endif

    SCReturnUInt(ret);
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
    MpmInitCtx(mpm_ctx, mpm_matcher, -1);
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
        SCFree(sh->mpm_ctx);

        /* ready for reuse */
        sh->mpm_ctx = NULL;
        sh->flags &= ~SIG_GROUP_HAVECONTENT;
    }

    /* uricontent */
    if (sh->flags & SIG_GROUP_HAVEURICONTENT && sh->mpm_uri_ctx != NULL &&
        !(sh->flags & SIG_GROUP_HEAD_MPM_URI_COPY)) {
        SCLogDebug("destroying mpm_uri_ctx %p (sh %p)", sh->mpm_uri_ctx, sh);
        mpm_table[sh->mpm_uri_ctx->mpm_type].DestroyCtx(sh->mpm_uri_ctx);
        SCFree(sh->mpm_uri_ctx);

        /* ready for reuse */
        sh->mpm_uri_ctx = NULL;
        sh->flags &= ~SIG_GROUP_HAVEURICONTENT;
    }
}

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

void DbgPrintSearchStats() {
#if 0
    printf(" - MPM: search %" PRId32 "\n", g_content_search);
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
                       * mpm match (for this pattern) */
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
     SCLogDebug("hash %" PRIu32 "", hash);
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
    ContentHash *ch = SCMalloc(sizeof(ContentHash));
    if (ch == NULL)
        return NULL;

    ch->ptr = ptr;
    ch->cnt = 1;
    ch->use = 0;
    ch->nosearch = 0;

    return ch;
}

void ContentHashFree(void *ch) {
    SCFree(ch);
}

/** \brief Predict a strength value for patterns
 *
 *  Patterns with high character diversity score higher.
 *  Alpha chars score not so high
 *  Other printable + a few common codes a little higher
 *  Everything else highest.
 *  Longer patterns score better than short patters.
 *
 *  \param pat pattern
 *  \param patlen length of the patternn
 *
 *  \retval s pattern score
 */
uint32_t PatternStrength(uint8_t *pat, uint16_t patlen) {
    uint8_t a[256];
    memset(&a, 0 ,sizeof(a));

    uint32_t s = 0;
    uint16_t u = 0;
    for (u = 0; u < patlen; u++) {
        if (a[pat[u]] == 0) {
            if (isalpha(pat[u]))
                s += 3;
            else if (isprint(pat[u]) || pat[u] == 0x00 || pat[u] == 0x01 || pat[u] == 0xFF)
                s += 4;
            else
                s += 6;

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

    fast_pattern = (uint32_t *)SCMalloc(sgh->sig_cnt * sizeof(uint32_t));
    if (fast_pattern == NULL)
        return -1;
    memset(fast_pattern, 0, sgh->sig_cnt * sizeof(uint32_t));

    HashTable *ht = HashTableInit(4096, ContentHashFunc, ContentHashCompareFunc, ContentHashFree);
    if (ht == NULL) {
        SCFree(fast_pattern);
        return -1;
    }

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
        for (sm = s->pmatch; sm != NULL; sm = sm->next) {
            if (sm->type == DETECT_CONTENT) {
                DetectContentData *co = (DetectContentData *)sm->ctx;
                if (co == NULL)
                    continue;

                if (co->flags & DETECT_CONTENT_FAST_PATTERN) {
                    fast_pattern[sig] = 1;
                    SCLogDebug("sig %"PRIu32" has a fast pattern, id %"PRIu32"", s->id, co->id);

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
                ContentHash *ch = ContentHashAlloc(s->pmatch->ctx);
                ch->nosearch = 1;
                ch->use = 1;
                SCLogDebug("sig %"PRIu32" has a fast pattern, id %"PRIu32"", s->id, ch->ptr->id);
            }
            continue;
        }

        for (sm = s->pmatch; sm != NULL; sm = sm->next) {
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
                    SCLogDebug("sig has just one pattern, so we know we will "
                               "use it in the mpm phase and no searching will "
                               "be necessary.");
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
                        //lookup_ch->use = 1;
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

    /* now determine which one to add to the mpm phase */
    for (sig = 0; sig < sgh->sig_cnt; sig++) {
        uint32_t num = sgh->match_array[sig];
        Signature *s = de_ctx->sig_array[num];
        if (s == NULL)
            continue;

        ContentHash *mpm_ch = NULL;
        SigMatch *sm = s->pmatch;
        for ( ; sm != NULL; sm = sm->next) {
            if (sm->type == DETECT_CONTENT) {
                DetectContentData *co = (DetectContentData *)sm->ctx;
                if (co == NULL)
                    continue;

                if (fast_pattern[sig] == 1) {
                    if (!(co->flags & DETECT_CONTENT_FAST_PATTERN)) {
                        SCLogDebug("not a fast pattern %"PRIu32"", co->id);
                        continue;
                    }
                    SCLogDebug("fast pattern %"PRIu32"", co->id);
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

                if (mpm_ch == NULL) {
                    SCLogDebug("mpm_ch == NULL, so selecting lookup_ch->ptr->id %"PRIu32"", lookup_ch->ptr->id);
                    mpm_ch = lookup_ch;
                } else {
                    uint32_t ls = PatternStrength(lookup_ch->ptr->content,lookup_ch->ptr->content_len);
                    uint32_t ss = PatternStrength(mpm_ch->ptr->content,mpm_ch->ptr->content_len);
                    if (ls > ss) {
                        SCLogDebug("lookup_ch->ptr->id %"PRIu32" selected over %"PRIu32"", lookup_ch->ptr->id, mpm_ch->ptr->id);
                        mpm_ch = lookup_ch;
                    }
                    else if (ls == ss) {
                        /* if 2 patterns are of equal strength, we pick the longest */
                        if (lookup_ch->ptr->content_len > mpm_ch->ptr->content_len) {
                            SCLogDebug("lookup_ch->ptr->id %"PRIu32" selected over %"PRIu32" as the first is longer", lookup_ch->ptr->id, mpm_ch->ptr->id);
                            mpm_ch = lookup_ch;
                        }
                    } else {
                        SCLogDebug("sticking with mpm_ch");
                    }
                }

                ContentHashFree(ch);
            }
        }
        /* now add the mpm_ch to the mpm ctx */
        if (mpm_ch != NULL) {
            DetectContentData *co = mpm_ch->ptr;
            uint16_t offset = s->flags & SIG_FLAG_RECURSIVE ? 0 : co->offset;
            uint16_t depth = s->flags & SIG_FLAG_RECURSIVE ? 0 : co->depth;
            offset = mpm_ch->cnt ? 0 : offset;
            depth = mpm_ch->cnt ? 0 : depth;
            uint8_t flags = 0;

            if (co->flags & DETECT_CONTENT_NOCASE) {
                mpm_table[sgh->mpm_ctx->mpm_type].AddPatternNocase(sgh->mpm_ctx, co->content, co->content_len, offset, depth, co->id, s->num, flags);
            } else {
                mpm_table[sgh->mpm_ctx->mpm_type].AddPattern(sgh->mpm_ctx, co->content, co->content_len, offset, depth, co->id, s->num, flags);
            }

            s->mpm_pattern_id = co->id;

            SCLogDebug("%"PRIu32" adding co->id %"PRIu32" to the mpm phase (s->num %"PRIu32")", s->id, co->id, s->num);
        } else {
            SCLogDebug("%"PRIu32" no mpm pattern selected", s->id);
        }
    }

    if (fast_pattern != NULL)
        SCFree(fast_pattern);
    HashTableFree(ht);
    return 0;
error:
    if (fast_pattern != NULL)
        SCFree(fast_pattern);
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
        for (sm = s->pmatch; sm != NULL; sm = sm->next) {
            if (sm->type == DETECT_CONTENT) {
                co_cnt++;
                s->flags |= SIG_FLAG_MPM;
            }
        }

        for (sm = s->umatch; sm != NULL; sm = sm->next) {
            if (sm->type == DETECT_URICONTENT) {
                ur_cnt++;
                s->flags |= SIG_FLAG_MPM_URI;
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
        sh->mpm_ctx = SCMalloc(sizeof(MpmCtx));
        if (sh->mpm_ctx == NULL)
            goto error;

        memset(sh->mpm_ctx, 0x00, sizeof(MpmCtx));
#ifndef __SC_CUDA_SUPPORT__
        MpmInitCtx(sh->mpm_ctx, de_ctx->mpm_matcher, -1);
#else
        MpmInitCtx(sh->mpm_ctx, de_ctx->mpm_matcher, de_ctx->cuda_rc_mod_handle);
#endif
    }
    if (sh->flags & SIG_GROUP_HAVEURICONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_URI_COPY)) {
        sh->mpm_uri_ctx = SCMalloc(sizeof(MpmCtx));
        if (sh->mpm_uri_ctx == NULL)
            goto error;

        memset(sh->mpm_uri_ctx, 0x00, sizeof(MpmCtx));
#ifndef __SC_CUDA_SUPPORT__
        MpmInitCtx(sh->mpm_uri_ctx, de_ctx->mpm_matcher, -1);
#else
        MpmInitCtx(sh->mpm_uri_ctx, de_ctx->mpm_matcher, de_ctx->cuda_rc_mod_handle);
#endif
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
        for (sm = s->pmatch; sm != NULL; sm = sm->next) {
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
            }
        }
        for (sm = s->umatch; sm != NULL; sm = sm->next) {
            if (sm->type == DETECT_URICONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_URI_COPY)) {
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
        for (sm = s->pmatch; sm != NULL; sm = sm->next) {
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
            }
        }
        //if (content_maxlen < 4 && content_cnt) printf(" (%" PRIu32 ", min %" PRIu32 ", max %" PRIu32 ")\n", content_cnt, content_minlen, content_maxlen);

        int content_depth_atleastone = 0;
        int content_offset_atleastone = 0;
        /* determine if we have at least one pattern with a depth */
        for (sm = s->pmatch; sm != NULL; sm = sm->next) {
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
            if (sh->mpm_content_maxlen > content_maxlen) {
                SCLogDebug("sgh (%p) sh->mpm_content_maxlen %u set to %u", sh, sh->mpm_content_maxlen, content_maxlen);
                sh->mpm_content_maxlen = content_maxlen;
            }
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
        for (sm = s->pmatch; sm != NULL; sm = sm->next) {
            if (sm->type == DETECT_CONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_COPY)) {
                DetectContentData *cd = (DetectContentData *)sm->ctx;

                if (cd->content_len > content_maxlen)
                    content_maxlen = cd->content_len;

                if (content_minlen == 0) content_minlen = cd->content_len;
                else if (cd->content_len < content_minlen)
                    content_minlen = cd->content_len;
            }
        }
        for (sm = s->umatch; sm != NULL; sm = sm->next) {
            if (sm->type == DETECT_URICONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_URI_COPY)) {
                DetectUricontentData *ud = (DetectUricontentData *)sm->ctx;
                if (ud->uricontent_len > uricontent_maxlen)
                    uricontent_maxlen = ud->uricontent_len;

                if (uricontent_minlen == 0) uricontent_minlen = ud->uricontent_len;
                else if (ud->uricontent_len < uricontent_minlen)
                    uricontent_minlen = ud->uricontent_len;
            }
        }
        char uricontent_mpmadded = 0;
        for (sm = s->umatch; sm != NULL; sm = sm->next) {
            if (sm->type == DETECT_URICONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_URI_COPY)) {
                DetectUricontentData *ud = (DetectUricontentData *)sm->ctx;

                /* only add the pattern if: we didn't add a pattern already,
                 * length is the same as maxlen (ie we only add the longest pattern) */
                if (!uricontent_mpmadded && uricontent_maxlen == ud->uricontent_len) {
                    uint8_t flags = 0;

                    if (ud->flags & DETECT_URICONTENT_NOCASE) {
                        mpm_table[sh->mpm_uri_ctx->mpm_type].AddPatternNocase(sh->mpm_uri_ctx, ud->uricontent, ud->uricontent_len, 0, 0, ud->id, s->num, flags);
                    } else {
                        mpm_table[sh->mpm_uri_ctx->mpm_type].AddPattern(sh->mpm_uri_ctx, ud->uricontent, ud->uricontent_len, 0, 0, ud->id, s->num, flags);
                    }
                    uricontent_mpmadded = 1;

                    s->mpm_uripattern_id = ud->id;
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
            g_uricontent_search++;
        }

        //sh->mpm_uri_ctx->PrintCtx(sh->mpm_uri_ctx);
    }

    return 0;
error:
    /* XXX */
    return -1;
}

/** \brief Pattern ID Hash for sharing pattern id's
 *
 *  A per detection engine hash to make sure each pattern has a unique
 *  global id but patterns that are the same share id's.
 */
typedef struct MpmPatternIdTableElmt_ {
    uint8_t *pattern;       /**< ptr to the pattern */
    uint16_t pattern_len;   /**< pattern len */
    uint32_t id;            /**< pattern id */
} MpmPatternIdTableElmt;

/** \brief Hash compare func for MpmPatternId api
 *  \retval 1 patterns are the same
 *  \retval 0 patterns are not the same
 **/
static char MpmPatternIdCompare(void *p1, uint16_t len1, void *p2, uint16_t len2) {
    SCEnter();
    BUG_ON(len1 < sizeof(MpmPatternIdTableElmt));
    BUG_ON(len2 < sizeof(MpmPatternIdTableElmt));

    MpmPatternIdTableElmt *e1 = (MpmPatternIdTableElmt *)p1;
    MpmPatternIdTableElmt *e2 = (MpmPatternIdTableElmt *)p2;

    if (e1->pattern_len != e2->pattern_len) {
        SCReturnInt(0);
    }

    if (memcmp(e1->pattern, e2->pattern, e1->pattern_len) != 0) {
        SCReturnInt(0);
    }

    SCReturnInt(1);
}

/** \brief Hash func for MpmPatternId api
 *  \retval hash hash value
 */
static uint32_t MpmPatternIdHashFunc(HashTable *ht, void *p, uint16_t len) {
    SCEnter();
    BUG_ON(len < sizeof(MpmPatternIdTableElmt));

    MpmPatternIdTableElmt *e = (MpmPatternIdTableElmt *)p;
    uint32_t hash = e->pattern_len;
    uint16_t u = 0;

    for (u = 0; u < e->pattern_len; u++) {
        hash += e->pattern[u];
    }

    SCReturnUInt(hash % ht->array_size);
}

/** \brief free a MpmPatternIdTableElmt */
static void MpmPatternIdTableElmtFree(void *e) {
    MpmPatternIdTableElmt *c = (MpmPatternIdTableElmt *)e;
    free(c->pattern);
    free(e);
}

/** \brief alloc initialize the MpmPatternIdHash */
MpmPatternIdStore *MpmPatternIdTableInitHash(void) {
    SCEnter();

    MpmPatternIdStore *ht = SCMalloc(sizeof(MpmPatternIdStore));
    BUG_ON(ht == NULL);
    memset(ht, 0x00, sizeof(MpmPatternIdStore));

    ht->hash = HashTableInit(65536, MpmPatternIdHashFunc, MpmPatternIdCompare, MpmPatternIdTableElmtFree);
    BUG_ON(ht->hash == NULL);

    SCReturnPtr(ht, "MpmPatternIdStore");
}

void MpmPatternIdTableFreeHash(MpmPatternIdStore *ht) {
   SCEnter();

    if (ht == NULL) {
        SCReturn;
    }

    if (ht->hash != NULL) {
        HashTableFree(ht->hash);
    }

    SCFree(ht);
    SCReturn;
}

uint32_t MpmPatternIdStoreGetMaxId(MpmPatternIdStore *ht) {
    if (ht == NULL) {
        return 0;
    }

    return ht->max_id;
}

/**
 *  \brief Get the pattern id for a content pattern
 *
 *  \param ht mpm pattern id hash table store
 *  \param co content pattern data
 *
 *  \retval id pattern id
 */
uint32_t DetectContentGetId(MpmPatternIdStore *ht, DetectContentData *co) {
    SCEnter();

    BUG_ON(ht == NULL || ht->hash == NULL);

    MpmPatternIdTableElmt *e = NULL;
    MpmPatternIdTableElmt *r = NULL;
    uint32_t id = 0;

    e = malloc(sizeof(MpmPatternIdTableElmt));
    BUG_ON(e == NULL);
    e->pattern = SCMalloc(co->content_len);
    BUG_ON(e->pattern == NULL);
    memcpy(e->pattern, co->content, co->content_len);
    e->pattern_len = co->content_len;
    e->id = 0;

    r = HashTableLookup(ht->hash, (void *)e, sizeof(MpmPatternIdTableElmt));
    if (r == NULL) {
        e->id = ht->max_id;
        ht->max_id++;
        id = e->id;

        int ret = HashTableAdd(ht->hash, e, sizeof(MpmPatternIdTableElmt));
        BUG_ON(ret != 0);

        e = NULL;

        ht->unique_patterns++;
    } else {
        id = r->id;

        ht->shared_patterns++;
    }

    if (e != NULL)
        free(e);

    SCReturnUInt(id);
}

/**
 *  \brief Get the pattern id for a uricontent pattern
 *
 *  \param ht mpm pattern id hash table store
 *  \param co content pattern data
 *
 *  \retval id pattern id
 */
uint32_t DetectUricontentGetId(MpmPatternIdStore *ht, DetectUricontentData *co) {
    SCEnter();

    BUG_ON(ht == NULL || ht->hash == NULL);

    MpmPatternIdTableElmt *e = NULL;
    MpmPatternIdTableElmt *r = NULL;
    uint32_t id = 0;

    e = malloc(sizeof(MpmPatternIdTableElmt));
    BUG_ON(e == NULL);
    e->pattern = SCMalloc(co->uricontent_len);
    BUG_ON(e->pattern == NULL);
    memcpy(e->pattern, co->uricontent, co->uricontent_len);
    e->pattern_len = co->uricontent_len;
    e->id = 0;

    r = HashTableLookup(ht->hash, (void *)e, sizeof(MpmPatternIdTableElmt));
    if (r == NULL) {
        e->id = ht->max_id;
        ht->max_id++;
        id = e->id;

        int ret = HashTableAdd(ht->hash, e, sizeof(MpmPatternIdTableElmt));
        BUG_ON(ret != 0);

        e = NULL;

        ht->unique_patterns++;
    } else {
        id = r->id;

        ht->shared_patterns++;
    }

    if (e != NULL)
        free(e);

    SCReturnUInt(id);
}


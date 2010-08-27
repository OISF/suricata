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

#include "app-layer-protos.h"

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

#include "stream.h"

#include "util-cuda-handlers.h"
#include "util-mpm-b2g-cuda.h"

#include "util-enum.h"
#include "util-debug.h"
#include "util-print.h"

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

/**
 *  \brief check if a signature has patterns that are to be inspected
 *         against a packets payload (as opposed to the stream payload)
 *
 *  \param s signature
 *
 *  \retval 1 true
 *  \retval 0 false
 */
int SignatureHasPacketContent(Signature *s) {
    SCEnter();

    if (s == NULL) {
        SCReturnInt(0);
    }

    if (!(s->flags & SIG_FLAG_MPM)) {
        SCLogDebug("no mpm");
        SCReturnInt(0);
    }

    if (s->alproto != ALPROTO_UNKNOWN) {
        SCLogDebug("inspecting app layer");
        SCReturnInt(0);
    }

    SigMatch *sm = s->pmatch;
    if (sm == NULL) {
        SCReturnInt(0);
    }

    for ( ;sm != NULL; sm = sm->next) {
        if (sm->type == DETECT_CONTENT) {
            SCReturnInt(1);
        }
    }

    SCReturnInt(0);
}

/**
 *  \brief check if a signature has patterns that are to be inspected
 *         against the stream payload (as opposed to the individual packets
 *         payload(s))
 *
 *  \param s signature
 *
 *  \retval 1 true
 *  \retval 0 false
 */
int SignatureHasStreamContent(Signature *s) {
    SCEnter();

    if (s == NULL) {
        SCReturnInt(0);
    }

    if (!(s->flags & SIG_FLAG_MPM)) {
        SCLogDebug("no mpm");
        SCReturnInt(0);
    }

    if (s->flags & SIG_FLAG_DSIZE) {
        SCLogDebug("dsize");
        SCReturnInt(0);
    }

    SigMatch *sm = s->pmatch;
    if (sm == NULL) {
        SCReturnInt(0);
    }

    for ( ;sm != NULL; sm = sm->next) {
        if (sm->type == DETECT_CONTENT) {
            SCReturnInt(1);
        }
    }

    SCReturnInt(0);
}


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

    if (p->cuda_mpm_enabled) {
        ret = B2gCudaResultsPostProcessing(p, det_ctx->sgh->mpm_ctx,
                                           &det_ctx->mtc, &det_ctx->pmq);
    } else {
        ret = mpm_table[det_ctx->sgh->mpm_ctx->mpm_type].Search(det_ctx->sgh->mpm_ctx,
                                                                &det_ctx->mtc,
                                                                &det_ctx->pmq,
                                                                p->payload,
                                                                p->payload_len);
    }

#endif

    SCReturnInt(ret);
}

/** \brief Uri Pattern match -- searches for one pattern per signature.
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *
 *  \retval ret number of matches
 */
uint32_t UriPatternSearch(DetectEngineThreadCtx *det_ctx,
                        uint8_t *uri, uint16_t uri_len)
{
    SCEnter();

    if (det_ctx->sgh->mpm_uri_ctx == NULL)
        SCReturnUInt(0U);

    //PrintRawDataFp(stdout, uri, uri_len);

    uint32_t ret;
    ret = mpm_table[det_ctx->sgh->mpm_uri_ctx->mpm_type].Search(det_ctx->sgh->mpm_uri_ctx,
            &det_ctx->mtcu, &det_ctx->pmq, uri, uri_len);

    SCReturnUInt(ret);
}

/** \brief Pattern match -- searches for only one pattern per signature.
 *
 *  \param tv threadvars
 *  \param det_ctx detection engine thread ctx
 *  \param p packet
 *  \param smsg stream msg (reassembled stream data)
 *  \param flags stream flags
 *
 *  \retval ret number of matches
 */
uint32_t StreamPatternSearch(ThreadVars *tv, DetectEngineThreadCtx *det_ctx,
        Packet *p, StreamMsg *smsg, uint8_t flags)
{
    SCEnter();

    uint32_t ret = 0;
    uint8_t cnt = 0;

    for ( ; smsg != NULL; smsg = smsg->next) {
        if (smsg->data.data_len < det_ctx->sgh->mpm_streamcontent_maxlen)
            continue;

        //PrintRawDataFp(stdout, smsg->data.data, smsg->data.data_len);

        uint32_t r = mpm_table[det_ctx->sgh->mpm_stream_ctx->mpm_type].Search(det_ctx->sgh->mpm_stream_ctx,
                &det_ctx->mtcs, &det_ctx->smsg_pmq[cnt], smsg->data.data, smsg->data.data_len);
        if (r > 0) {
            ret += r;

            SCLogDebug("smsg match stored in det_ctx->smsg_pmq[%u]", cnt);

            /* merge results with overall pmq */
            PmqMerge(&det_ctx->smsg_pmq[cnt], &det_ctx->pmq);
        }

        cnt++;
    }

    SCReturnInt(ret);
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
    /* stream content */
    if (det_ctx->sgh->mpm_stream_ctx != NULL && mpm_table[det_ctx->sgh->mpm_stream_ctx->mpm_type].Cleanup != NULL) {
        mpm_table[det_ctx->sgh->mpm_stream_ctx->mpm_type].Cleanup(&det_ctx->mtcs);
    }
}

void StreamPatternCleanup(ThreadVars *t, DetectEngineThreadCtx *det_ctx, StreamMsg *smsg) {
    uint8_t cnt = 0;

    while (smsg != NULL) {
        PmqReset(&det_ctx->smsg_pmq[cnt]);

        smsg = smsg->next;
        cnt++;
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

    /* stream content */
    if (sh->flags & SIG_GROUP_HAVESTREAMCONTENT) {
        if (sh->mpm_stream_ctx != NULL) {
            if (!(sh->flags & SIG_GROUP_HEAD_MPM_STREAM_COPY)) {
                SCLogDebug("destroying mpm_stream_ctx %p (sh %p)", sh->mpm_stream_ctx, sh);
                mpm_table[sh->mpm_stream_ctx->mpm_type].DestroyCtx(sh->mpm_stream_ctx);
                SCFree(sh->mpm_stream_ctx);

                /* ready for reuse */
                sh->mpm_stream_ctx = NULL;
                sh->flags &= ~SIG_GROUP_HAVESTREAMCONTENT;
            }
        }
    }
}

/** \brief Hash for looking up contents that are most used,
 *         always used, etc. */
typedef struct ContentHash_ {
    DetectContentData *ptr;
    uint16_t cnt;
    uint8_t use; /* use no matter what */
} ContentHash;

typedef struct UricontentHash_ {
    DetectUricontentData *ptr;
    uint16_t cnt;
    uint8_t use; /* use no matter what */
} UricontentHash;

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

uint32_t UricontentHashFunc(HashTable *ht, void *data, uint16_t datalen) {
     UricontentHash *ch = (UricontentHash *)data;
     DetectUricontentData *ud = ch->ptr;
     uint32_t hash = 0;
     int i;
     for (i = 0; i < ud->uricontent_len; i++) {
         hash += ud->uricontent[i];
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

char UricontentHashCompareFunc(void *data1, uint16_t len1, void *data2, uint16_t len2) {
    UricontentHash *ch1 = (UricontentHash *)data1;
    UricontentHash *ch2 = (UricontentHash *)data2;
    DetectUricontentData *ud1 = ch1->ptr;
    DetectUricontentData *ud2 = ch2->ptr;

    if (ud1->uricontent_len == ud2->uricontent_len &&
        memcmp(ud1->uricontent, ud2->uricontent, ud1->uricontent_len) == 0)
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

    return ch;
}

UricontentHash *UricontentHashAlloc(DetectUricontentData *ptr) {
    UricontentHash *ch = SCMalloc(sizeof(UricontentHash));
    if (ch == NULL)
        return NULL;

    ch->ptr = ptr;
    ch->cnt = 1;
    ch->use = 0;

    return ch;
}

void ContentHashFree(void *ch) {
    SCFree(ch);
}

void UricontentHashFree(void *ch) {
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
        Signature *s = sgh->match_array[sig];
        if (s == NULL)
            continue;

        if (SignatureHasPacketContent(s) == 0) {
            continue;
        }

        int cnt = 0;
        SigMatch *sm;

        /* get the total no of patterns in this Signature, as well as find out
         * if we have a fast_pattern set in this Signature */
        for (sm = s->pmatch; sm != NULL; sm = sm->next) {
            if (sm->type != DETECT_CONTENT)
                continue;

            DetectContentData *co = (DetectContentData *)sm->ctx;
            if (co == NULL)
                continue;

            cnt++;

            /* special handling of fast pattern keyword */
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
                    lookup_ch->cnt++;
                    ContentHashFree(ch);
                }
            }
        }

        if (fast_pattern[sig] == 1) {
            continue;
        }

        for (sm = s->pmatch; sm != NULL; sm = sm->next) {
            if (sm->type != DETECT_CONTENT)
                continue;

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
                        "use it in the mpm phase.");
                ch->use = 1;
            }

            ContentHash *lookup_ch = (ContentHash *)HashTableLookup(ht, ch, 0);
            if (lookup_ch == NULL) {
                int r = HashTableAdd(ht, ch, 0);
                if (r < 0)
                    printf("Add hash failed\n");
            } else {
                lookup_ch->use = ch->use;

                lookup_ch->cnt++;
                ContentHashFree(ch);
            }
        }
    }

    /* now determine which one to add to the mpm phase */
    for (sig = 0; sig < sgh->sig_cnt; sig++) {
        Signature *s = sgh->match_array[sig];
        if (s == NULL || s->pmatch == NULL)
            continue;

        if (SignatureHasPacketContent(s) == 0) {
            continue;
        }

        ContentHash *mpm_ch = NULL;
        SigMatch *sm = NULL;

        for (sm = s->pmatch; sm != NULL; sm = sm->next) {
            if (sm->type != DETECT_CONTENT)
                continue;

            DetectContentData *co = (DetectContentData *)sm->ctx;
            if (co == NULL)
                continue;

            /* skip in case of:
             * 1. we expect a fastpattern but this isn't it
             * 2. we have a smaller content than mpm_content_maxlen */
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
                        SCLogDebug("lookup_ch->ptr->id %"PRIu32" selected over %"PRIu32" as the first is longer",
                                lookup_ch->ptr->id, mpm_ch->ptr->id);
                        mpm_ch = lookup_ch;
                    }
                } else {
                    SCLogDebug("sticking with mpm_ch");
                }
            }

            ContentHashFree(ch);
        }

        /* now add the mpm_ch to the mpm ctx */
        if (mpm_ch != NULL) {
            DetectContentData *co = mpm_ch->ptr;
            uint16_t offset = s->flags & SIG_FLAG_RECURSIVE ? 0 : co->offset;
            uint16_t depth = s->flags & SIG_FLAG_RECURSIVE ? 0 : co->depth;
            offset = mpm_ch->cnt ? 0 : offset;
            depth = mpm_ch->cnt ? 0 : depth;
            uint8_t flags = 0;
            char scan_negated = 0;

            /* see if our content is actually negated */
            SigMatch *tmpsm = s->pmatch;
            for ( ; tmpsm != NULL; tmpsm = tmpsm->next) {
                if (tmpsm->type != DETECT_CONTENT)
                    continue;

                DetectContentData *tmp = (DetectContentData *)tmpsm->ctx;
                if (tmp == NULL)
                    continue;

                if (co->id == tmp->id) {
                    if (tmp->flags & DETECT_CONTENT_NEGATED) {
                        scan_negated = 1;
                    }
                    break;
                }
            }

            /* add the content to the "packet" mpm */
            if (co->flags & DETECT_CONTENT_NOCASE) {
                mpm_table[sgh->mpm_ctx->mpm_type].AddPatternNocase(sgh->mpm_ctx,
                        co->content, co->content_len, offset, depth, co->id,
                        s->num, flags);
            } else {
                mpm_table[sgh->mpm_ctx->mpm_type].AddPattern(sgh->mpm_ctx,
                        co->content, co->content_len, offset, depth, co->id,
                        s->num, flags);
            }

            /* tell matcher we are inspecting packet */
            s->flags |= SIG_FLAG_MPM_PACKET;

            s->mpm_pattern_id = co->id;
            if (scan_negated) {
                SCLogDebug("flagging sig %"PRIu32" to be looking for negated mpm", s->id);
                s->flags |= SIG_FLAG_MPM_NEGCONTENT;
            }

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

/** \brief Setup the content portion of the sig group head */
static int PatternMatchPreprarePopulateMpmStream(DetectEngineCtx *de_ctx, SigGroupHead *sgh) {
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
        Signature *s = sgh->match_array[sig];
        if (s == NULL)
            continue;

        if (SignatureHasStreamContent(s) == 0) {
            continue;
        }

        int cnt = 0;
        SigMatch *sm;

        /* get the total no of patterns in this Signature, as well as find out
         * if we have a fast_pattern set in this Signature */
        for (sm = s->pmatch; sm != NULL; sm = sm->next) {
            if (sm->type != DETECT_CONTENT)
                continue;

            DetectContentData *co = (DetectContentData *)sm->ctx;
            if (co == NULL)
                continue;

            cnt++;

            /* special handling of fast pattern keyword */
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
                    lookup_ch->cnt++;
                    ContentHashFree(ch);
                }
            }
        }

        if (fast_pattern[sig] == 1) {
            continue;
        }

        for (sm = s->pmatch; sm != NULL; sm = sm->next) {
            if (sm->type != DETECT_CONTENT)
                continue;

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
                        "use it in the mpm phase.");
                ch->use = 1;
            }

            ContentHash *lookup_ch = (ContentHash *)HashTableLookup(ht, ch, 0);
            if (lookup_ch == NULL) {
                int r = HashTableAdd(ht, ch, 0);
                if (r < 0)
                    printf("Add hash failed\n");
            } else {
                lookup_ch->use = ch->use;

                lookup_ch->cnt++;
                ContentHashFree(ch);
            }
        }
    }

    /* now determine which one to add to the mpm phase */
    for (sig = 0; sig < sgh->sig_cnt; sig++) {
        Signature *s = sgh->match_array[sig];
        if (s == NULL || s->pmatch == NULL)
            continue;

        if (SignatureHasStreamContent(s) == 0) {
            continue;
        }

        ContentHash *mpm_ch = NULL;
        SigMatch *sm = NULL;

        for (sm = s->pmatch; sm != NULL; sm = sm->next) {
            if (sm->type != DETECT_CONTENT)
                continue;

            DetectContentData *co = (DetectContentData *)sm->ctx;
            if (co == NULL)
                continue;

            /* skip in case of:
             * 1. we expect a fastpattern but this isn't it
             * 2. we have a smaller content than mpm_content_maxlen */
            if (fast_pattern[sig] == 1) {
                if (!(co->flags & DETECT_CONTENT_FAST_PATTERN)) {
                    SCLogDebug("not a fast pattern %"PRIu32"", co->id);
                    continue;
                }
                SCLogDebug("fast pattern %"PRIu32"", co->id);
            } else if (co->content_len < sgh->mpm_streamcontent_maxlen) {
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
                        SCLogDebug("lookup_ch->ptr->id %"PRIu32" selected over %"PRIu32" as the first is longer",
                                lookup_ch->ptr->id, mpm_ch->ptr->id);
                        mpm_ch = lookup_ch;
                    }
                } else {
                    SCLogDebug("sticking with mpm_ch");
                }
            }

            ContentHashFree(ch);
        }

        /* now add the mpm_ch to the mpm ctx */
        if (mpm_ch != NULL) {
            DetectContentData *co = mpm_ch->ptr;
            uint16_t offset = s->flags & SIG_FLAG_RECURSIVE ? 0 : co->offset;
            uint16_t depth = s->flags & SIG_FLAG_RECURSIVE ? 0 : co->depth;
            offset = mpm_ch->cnt ? 0 : offset;
            depth = mpm_ch->cnt ? 0 : depth;
            uint8_t flags = 0;
            char scan_negated = 0;

            /* see if our content is actually negated */
            SigMatch *tmpsm = s->pmatch;
            for ( ; tmpsm != NULL; tmpsm = tmpsm->next) {
                if (tmpsm->type != DETECT_CONTENT)
                    continue;

                DetectContentData *tmp = (DetectContentData *)tmpsm->ctx;
                if (tmp == NULL)
                    continue;

                if (co->id == tmp->id) {
                    if (tmp->flags & DETECT_CONTENT_NEGATED) {
                        scan_negated = 1;
                    }
                    break;
                }
            }

            SCLogDebug("mpm_stream_ctx %p", sgh->mpm_stream_ctx);
            /* add the content to the "stream" mpm */
            if (co->flags & DETECT_CONTENT_NOCASE) {
                mpm_table[sgh->mpm_stream_ctx->mpm_type].AddPatternNocase(sgh->mpm_stream_ctx,
                        co->content, co->content_len, offset, depth, co->id, s->num, flags);
            } else {
                mpm_table[sgh->mpm_stream_ctx->mpm_type].AddPattern(sgh->mpm_stream_ctx,
                        co->content, co->content_len, offset, depth, co->id, s->num, flags);
            }

            /* tell matcher we are inspecting stream */
            s->flags |= SIG_FLAG_MPM_STREAM;

            s->mpm_stream_pattern_id = co->id;
            if (scan_negated) {
                SCLogDebug("flagging sig %"PRIu32" to be looking for negated mpm", s->id);
                s->flags |= SIG_FLAG_MPM_NEGCONTENT;
            }

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

/** \brief Setup the content portion of the sig group head */
static int PatternMatchPreprarePopulateMpmUri(DetectEngineCtx *de_ctx, SigGroupHead *sgh) {
    uint32_t sig;
#if 0
    uint32_t *fast_pattern = NULL;
    fast_pattern = (uint32_t *)SCMalloc(sgh->sig_cnt * sizeof(uint32_t));
    if (fast_pattern == NULL)
        return -1;
    memset(fast_pattern, 0, sgh->sig_cnt * sizeof(uint32_t));
#endif
    HashTable *ht = HashTableInit(4096, UricontentHashFunc, UricontentHashCompareFunc, UricontentHashFree);
    if (ht == NULL) {
#if 0
        SCFree(fast_pattern);
#endif
        return -1;
    }

    /* add all the contents to a counting hash */
    for (sig = 0; sig < sgh->sig_cnt; sig++) {
        Signature *s = sgh->match_array[sig];
        if (s == NULL)
            continue;

        int cnt = 0;
        SigMatch *sm;

        /* get the total no of patterns in this Signature, as well as find out
         * if we have a fast_pattern set in this Signature */
        for (sm = s->umatch; sm != NULL; sm = sm->next) {
            if (sm->type != DETECT_URICONTENT)
                continue;

            DetectUricontentData *ud = (DetectUricontentData *)sm->ctx;
            if (ud == NULL)
                continue;

            cnt++;
#if 0
            /* special handling of fast pattern keyword */
            if (co->flags & DETECT_URICONTENT_FAST_PATTERN) {
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
                    lookup_ch->cnt++;
                    ContentHashFree(ch);
                }
            }
#endif
        }
#if 0
        if (fast_pattern[sig] == 1) {
            continue;
        }
#endif
        for (sm = s->umatch; sm != NULL; sm = sm->next) {
            if (sm->type != DETECT_URICONTENT)
                continue;

            DetectUricontentData *ud = (DetectUricontentData *)sm->ctx;
            if (ud == NULL)
                continue;

            if (ud->uricontent_len < sgh->mpm_uricontent_maxlen) {
                continue;
            }

            UricontentHash *ch = UricontentHashAlloc(ud);
            if (ch == NULL)
                goto error;

            if (cnt == 1) {
                SCLogDebug("sig has just one pattern, so we know we will "
                        "use it in the mpm phase.");
                ch->use = 1;
            }

            UricontentHash *lookup_ch = (UricontentHash *)HashTableLookup(ht, ch, 0);
            if (lookup_ch == NULL) {
                int r = HashTableAdd(ht, ch, 0);
                if (r < 0)
                    printf("Add hash failed\n");
            } else {
                lookup_ch->use = ch->use;

                lookup_ch->cnt++;
                UricontentHashFree(ch);
            }
        }
    }

    /* now determine which one to add to the mpm phase */
    for (sig = 0; sig < sgh->sig_cnt; sig++) {
        Signature *s = sgh->match_array[sig];
        if (s == NULL || s->umatch == NULL)
            continue;

        UricontentHash *mpm_ch = NULL;
        SigMatch *sm = NULL;

        for (sm = s->umatch; sm != NULL; sm = sm->next) {
            if (sm->type != DETECT_URICONTENT)
                continue;

            DetectUricontentData *ud = (DetectUricontentData *)sm->ctx;
            if (ud == NULL)
                continue;

            /* skip in case of:
             * 1. we expect a fastpattern but this isn't it
             * 2. we have a smaller content than mpm_content_maxlen */
#if 0
            if (fast_pattern[sig] == 1) {
                if (!(co->flags & DETECT_CONTENT_FAST_PATTERN)) {
                    SCLogDebug("not a fast pattern %"PRIu32"", co->id);
                    continue;
                }
                SCLogDebug("fast pattern %"PRIu32"", co->id);

            } else
#endif
            if (ud->uricontent_len < sgh->mpm_uricontent_maxlen) {
                continue;
            }

            UricontentHash *ch = UricontentHashAlloc(ud);
            if (ch == NULL)
                goto error;

            UricontentHash *lookup_ch = (UricontentHash *)HashTableLookup(ht, ch, 0);
            if (lookup_ch == NULL) {
                continue;
            }

            SCLogDebug("lookup_ch->use %u, cnt %u", lookup_ch->use, lookup_ch->cnt);

            if (mpm_ch == NULL) {
                SCLogDebug("mpm_ch == NULL, so selecting lookup_ch->ptr->id %"PRIu32"", lookup_ch->ptr->id);
                mpm_ch = lookup_ch;
            } else {
                uint32_t ls = PatternStrength(lookup_ch->ptr->uricontent,lookup_ch->ptr->uricontent_len);
                uint32_t ss = PatternStrength(mpm_ch->ptr->uricontent,mpm_ch->ptr->uricontent_len);
                if (ls > ss) {
                    SCLogDebug("lookup_ch->ptr->id %"PRIu32" selected over %"PRIu32"", lookup_ch->ptr->id, mpm_ch->ptr->id);
                    mpm_ch = lookup_ch;
                }
                else if (ls == ss) {
                    /* if 2 patterns are of equal strength, we pick the longest */
                    if (lookup_ch->ptr->uricontent_len > mpm_ch->ptr->uricontent_len) {
                        SCLogDebug("lookup_ch->ptr->id %"PRIu32" selected over %"PRIu32" as the first is longer",
                                lookup_ch->ptr->id, mpm_ch->ptr->id);
                        mpm_ch = lookup_ch;
                    }
                } else {
                    SCLogDebug("sticking with mpm_ch");
                }
            }

            UricontentHashFree(ch);
        }

        /* now add the mpm_ch to the mpm ctx */
        if (mpm_ch != NULL) {
            DetectUricontentData *ud = mpm_ch->ptr;
            uint8_t flags = 0;
#if 0
            /* see if our content is actually negated */
            SigMatch *tmpsm = s->pmatch;
            for ( ; tmpsm != NULL; tmpsm = tmpsm->next) {
                if (tmpsm->type != DETECT_CONTENT)
                    continue;

                DetectContentData *tmp = (DetectContentData *)tmpsm->ctx;
                if (tmp == NULL)
                    continue;

                if (co->id == tmp->id) {
                    if (tmp->flags & DETECT_CONTENT_NEGATED) {
                        scan_negated = 1;
                    }
                    break;
                }
            }
#endif
            /* add the content to the "packet" mpm */
            if (ud->flags & DETECT_URICONTENT_NOCASE) {
                mpm_table[sgh->mpm_uri_ctx->mpm_type].AddPatternNocase(sgh->mpm_uri_ctx,
                        ud->uricontent, ud->uricontent_len, 0, 0, ud->id, s->num, flags);
            } else {
                mpm_table[sgh->mpm_uri_ctx->mpm_type].AddPattern(sgh->mpm_uri_ctx,
                        ud->uricontent, ud->uricontent_len, 0, 0, ud->id,
                        s->num, flags);
            }

            s->mpm_uripattern_id = ud->id;

            SCLogDebug("%"PRIu32" adding ud->id %"PRIu32" to the mpm phase (s->num %"PRIu32")", s->id, ud->id, s->num);
        } else {
            SCLogDebug("%"PRIu32" no mpm pattern selected", s->id);
        }
    }

#if 0
    if (fast_pattern != NULL)
        SCFree(fast_pattern);
#endif
    HashTableFree(ht);
    return 0;
error:
#if 0
    if (fast_pattern != NULL)
        SCFree(fast_pattern);
#endif
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
    uint32_t has_co_packet = 0; /**< our sgh has packet payload inspecting content */
    uint32_t has_co_stream = 0; /**< our sgh has stream inspecting content */
    uint32_t has_co_uri = 0;    /**< our sgh has uri inspecting content */
    uint32_t cnt = 0;
    uint32_t sig = 0;

    if (!(sh->flags & SIG_GROUP_HEAD_MPM_COPY))
        sh->mpm_content_maxlen = 0;

    if (!(sh->flags & SIG_GROUP_HEAD_MPM_URI_COPY))
        sh->mpm_uricontent_maxlen = 0;

    if (!(sh->flags & SIG_GROUP_HEAD_MPM_STREAM_COPY))
        sh->mpm_streamcontent_maxlen = 0;

    /* see if this head has content and/or uricontent */
    for (sig = 0; sig < sh->sig_cnt; sig++) {
        s = sh->match_array[sig];
        if (s == NULL)
            continue;

        if (SignatureHasPacketContent(s) == 1) {
            has_co_packet = 1;
        }
        if (SignatureHasStreamContent(s) == 1) {
            has_co_stream = 1;
        }

        for (sm = s->umatch; sm != NULL; sm = sm->next) {
            if (sm->type == DETECT_URICONTENT) {
                has_co_uri = 1;
            }
        }
    }

    if (has_co_packet > 0) {
        sh->flags |= SIG_GROUP_HAVECONTENT;
    }
    if (has_co_stream > 0) {
        sh->flags |= SIG_GROUP_HAVESTREAMCONTENT;
    }
    if (has_co_uri > 0) {
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

    if (sh->flags & SIG_GROUP_HAVESTREAMCONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_STREAM_COPY)) {
        sh->mpm_stream_ctx = SCMalloc(sizeof(MpmCtx));
        if (sh->mpm_stream_ctx == NULL)
            goto error;

        memset(sh->mpm_stream_ctx, 0x00, sizeof(MpmCtx));
#ifndef __SC_CUDA_SUPPORT__
        MpmInitCtx(sh->mpm_stream_ctx, de_ctx->mpm_matcher, -1);
#else
        MpmInitCtx(sh->mpm_stream_ctx, de_ctx->mpm_matcher, de_ctx->cuda_rc_mod_handle);
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

    /* for each signature in this group do */
    for (sig = 0; sig < sh->sig_cnt; sig++) {
        s = sh->match_array[sig];
        if (s == NULL)
            continue;

        cnt++;

        char content_added = 0;
        char uricontent_added = 0;
        char stream_content_added = 0;
        uint16_t content_maxlen = 0, stream_content_maxlen = 0;
        uint16_t content_minlen = 0, stream_content_minlen = 0;
        uint16_t uricontent_maxlen = 0;
        uint16_t uricontent_minlen = 0;

        SigMatch *sm;

        /* determine the length of the longest pattern */
        if (sh->flags & SIG_GROUP_HAVECONTENT &&
                !(sh->flags & SIG_GROUP_HEAD_MPM_COPY))
        {
            if (SignatureHasPacketContent(s) == 1) {
                for (sm = s->pmatch; sm != NULL; sm = sm->next) {
                    if (sm->type != DETECT_CONTENT)
                        continue;

                    DetectContentData *cd = (DetectContentData *)sm->ctx;
                    if (cd == NULL)
                        continue;

                    if (cd->content_len > content_maxlen)
                        content_maxlen = cd->content_len;

                    if (content_minlen == 0)
                        content_minlen = cd->content_len;
                    else if (cd->content_len < content_minlen)
                        content_minlen = cd->content_len;

                    if (!content_added) {
                        content_added = 1;
                    }
                }

                if (content_added > 0) {
                    if (sh->mpm_content_maxlen == 0)
                        sh->mpm_content_maxlen = content_maxlen;
                    if (sh->mpm_content_maxlen > content_maxlen) {
                        SCLogDebug("sgh (%p) sh->mpm_content_maxlen %u set to %u",
                                sh, sh->mpm_content_maxlen, content_maxlen);

                        sh->mpm_content_maxlen = content_maxlen;
                    }
                }
            }
        }

        if (sh->flags & SIG_GROUP_HAVESTREAMCONTENT &&
                !(sh->flags & SIG_GROUP_HEAD_MPM_STREAM_COPY))
        {
            if (SignatureHasStreamContent(s) == 1) {
                for (sm = s->pmatch; sm != NULL; sm = sm->next) {
                    if (sm->type != DETECT_CONTENT)
                        continue;

                    DetectContentData *cd = (DetectContentData *)sm->ctx;
                    if (cd == NULL)
                        continue;

                    if (cd->content_len > stream_content_maxlen)
                        stream_content_maxlen = cd->content_len;

                    if (stream_content_minlen == 0)
                        stream_content_minlen = cd->content_len;
                    else if (cd->content_len < stream_content_minlen)
                        stream_content_minlen = cd->content_len;

                    if (!stream_content_added) {
                        stream_content_added = 1;
                    }
                }

                if (stream_content_added > 0) {
                    if (sh->mpm_streamcontent_maxlen == 0)
                        sh->mpm_streamcontent_maxlen = stream_content_maxlen;
                    if (sh->mpm_streamcontent_maxlen > stream_content_maxlen) {
                        SCLogDebug("sgh (%p) sh->mpm_streamcontent_maxlen %u set to %u",
                            sh, sh->mpm_streamcontent_maxlen, stream_content_maxlen);

                        sh->mpm_streamcontent_maxlen = stream_content_maxlen;
                    }
                }
            }
        }

        if (sh->flags & SIG_GROUP_HAVEURICONTENT &&
                !(sh->flags & SIG_GROUP_HEAD_MPM_URI_COPY))
        {
            /* determine the length of the longest pattern */
            for (sm = s->umatch; sm != NULL; sm = sm->next) {
                if (sm->type != DETECT_URICONTENT)
                    continue;

                DetectUricontentData *ud = (DetectUricontentData *)sm->ctx;
                if (ud == NULL)
                    continue;

                if (ud->uricontent_len > uricontent_maxlen)
                    uricontent_maxlen = ud->uricontent_len;

                if (uricontent_minlen == 0)
                    uricontent_minlen = ud->uricontent_len;
                else if (ud->uricontent_len < uricontent_minlen)
                    uricontent_minlen = ud->uricontent_len;

                if (!uricontent_added) {
                    uricontent_added = 1;
                }
            }

            if (uricontent_added) {
                if (sh->mpm_uricontent_maxlen == 0)
                    sh->mpm_uricontent_maxlen = uricontent_maxlen;
                if (sh->mpm_uricontent_maxlen > uricontent_maxlen)
                    sh->mpm_uricontent_maxlen = uricontent_maxlen;
            }
        }
    }

    /* uricontent */
    if (sh->flags & SIG_GROUP_HAVEURICONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_URI_COPY)) {
        PatternMatchPreprarePopulateMpmUri(de_ctx, sh);

        if (mpm_table[sh->mpm_uri_ctx->mpm_type].Prepare != NULL) {
            mpm_table[sh->mpm_uri_ctx->mpm_type].Prepare(sh->mpm_uri_ctx);
        }

        //sh->mpm_uri_ctx->PrintCtx(sh->mpm_uri_ctx);

    }

    /* content */
    if (sh->flags & SIG_GROUP_HAVECONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_COPY)) {
        PatternMatchPreprarePopulateMpm(de_ctx, sh);

        if (mpm_table[sh->mpm_ctx->mpm_type].Prepare != NULL) {
            mpm_table[sh->mpm_ctx->mpm_type].Prepare(sh->mpm_ctx);
        }
    }

    /* stream content */
    if (sh->flags & SIG_GROUP_HAVESTREAMCONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_STREAM_COPY)) {
        PatternMatchPreprarePopulateMpmStream(de_ctx, sh);
        SCLogDebug("preparing mpm_stream_ctx %p", sh->mpm_stream_ctx);
        if (mpm_table[sh->mpm_stream_ctx->mpm_type].Prepare != NULL) {
            mpm_table[sh->mpm_stream_ctx->mpm_type].Prepare(sh->mpm_stream_ctx);
        }
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
    SCEnter();
    MpmPatternIdTableElmt *c = (MpmPatternIdTableElmt *)e;
    SCFree(c->pattern);
    SCFree(c);
    SCReturn;
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
 *  \initonly
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
        MpmPatternIdTableElmtFree(e);

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
        MpmPatternIdTableElmtFree(e);

    SCReturnUInt(id);
}


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
#include "detect-parse.h"
#include "util-mpm.h"
#include "conf.h"
#include "detect-fast-pattern.h"

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
#include "util-memcmp.h"

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

#define POPULATE_MPM_AVOID_PACKET_MPM_PATTERNS 0x01
#define POPULATE_MPM_AVOID_STREAM_MPM_PATTERNS 0x02
#define POPULATE_MPM_AVOID_URI_MPM_PATTERNS 0x04

/* holds the string-enum mapping for the enums that define the different MPM
 * algos in util-mpm.h */
SCEnumCharMap sc_mpm_algo_map[] = {
    { "b2g",      MPM_B2G },
    { "b3g",      MPM_B3G },
    { "wumanber", MPM_WUMANBER },
    { "ac",       MPM_AC },
    { "ac-gfbs",  MPM_AC_GFBS },
#ifdef __SC_CUDA_SUPPORT__
    { "b2g_cuda", MPM_B2G_CUDA },
#endif
    { "b2gc",     MPM_B2GC },
    { "b2gm",     MPM_B2GM },
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

    SigMatch *sm = s->sm_lists[DETECT_SM_LIST_PMATCH];
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

    SigMatch *sm = s->sm_lists[DETECT_SM_LIST_PMATCH];
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
        if (!MpmFactoryIsMpmCtxAvailable(sh->mpm_ctx)) {
            mpm_table[sh->mpm_ctx->mpm_type].DestroyCtx(sh->mpm_ctx);
            SCFree(sh->mpm_ctx);
        }

        /* ready for reuse */
        sh->mpm_ctx = NULL;
        sh->flags &= ~SIG_GROUP_HAVECONTENT;
    }

    /* uricontent */
    if (sh->flags & SIG_GROUP_HAVEURICONTENT && sh->mpm_uri_ctx != NULL &&
        !(sh->flags & SIG_GROUP_HEAD_MPM_URI_COPY)) {
        SCLogDebug("destroying mpm_uri_ctx %p (sh %p)", sh->mpm_uri_ctx, sh);
        if (!MpmFactoryIsMpmCtxAvailable(sh->mpm_uri_ctx)) {
            mpm_table[sh->mpm_uri_ctx->mpm_type].DestroyCtx(sh->mpm_uri_ctx);
            SCFree(sh->mpm_uri_ctx);
        }

        /* ready for reuse */
        sh->mpm_uri_ctx = NULL;
        sh->flags &= ~SIG_GROUP_HAVEURICONTENT;
    }

    /* stream content */
    if (sh->flags & SIG_GROUP_HAVESTREAMCONTENT) {
        if (sh->mpm_stream_ctx != NULL) {
            if (!(sh->flags & SIG_GROUP_HEAD_MPM_STREAM_COPY)) {
                SCLogDebug("destroying mpm_stream_ctx %p (sh %p)", sh->mpm_stream_ctx, sh);
                if (!MpmFactoryIsMpmCtxAvailable(sh->mpm_stream_ctx)) {
                    mpm_table[sh->mpm_stream_ctx->mpm_type].DestroyCtx(sh->mpm_stream_ctx);
                    SCFree(sh->mpm_stream_ctx);
                }

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
    DetectContentData *ptr;
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
     DetectContentData *ud = ch->ptr;
     uint32_t hash = 0;
     int i;
     for (i = 0; i < ud->content_len; i++) {
         hash += ud->content[i];
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
        ((co1->flags & DETECT_CONTENT_NOCASE) == (co2->flags & DETECT_CONTENT_NOCASE)) &&
        SCMemcmp(co1->content, co2->content, co1->content_len) == 0)
        return 1;

    return 0;
}

char UricontentHashCompareFunc(void *data1, uint16_t len1, void *data2, uint16_t len2) {
    UricontentHash *ch1 = (UricontentHash *)data1;
    UricontentHash *ch2 = (UricontentHash *)data2;
    DetectContentData *ud1 = ch1->ptr;
    DetectContentData *ud2 = ch2->ptr;

    if (ud1->content_len == ud2->content_len &&
        ((ud1->flags & DETECT_CONTENT_NOCASE) == (ud2->flags & DETECT_CONTENT_NOCASE)) &&
        SCMemcmp(ud1->content, ud2->content, ud1->content_len) == 0)
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

UricontentHash *UricontentHashAlloc(DetectContentData *ptr) {
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

static void PopulateMpmAddPatternToMpm(DetectEngineCtx *de_ctx,
                                       SigGroupHead *sgh, Signature *s,
                                       SigMatch *mpm_sm)
{
            /* now add the mpm_ch to the mpm ctx */
        if (mpm_sm != NULL) {
            uint8_t flags = 0;

            DetectContentData *cd = NULL;
            DetectContentData *ud = NULL;
            switch (mpm_sm->type) {
                case DETECT_CONTENT:
                {
                    cd = (DetectContentData *)mpm_sm->ctx;
                    if (cd->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) {
                        /* add the content to the "packet" mpm */
                        if (SignatureHasPacketContent(s) &&
                            (sgh->flags & SIG_GROUP_HAVECONTENT &&
                             !(sgh->flags & SIG_GROUP_HEAD_MPM_COPY))) {

                            if (cd->flags & DETECT_CONTENT_NOCASE) {
                                mpm_table[sgh->mpm_ctx->mpm_type].
                                    AddPatternNocase(sgh->mpm_ctx,
                                                     cd->content + cd->fp_chop_offset,
                                                     cd->fp_chop_len,
                                                     0, 0, cd->id, s->num, flags);
                            } else {
                                mpm_table[sgh->mpm_ctx->mpm_type].
                                    AddPattern(sgh->mpm_ctx,
                                               cd->content + cd->fp_chop_offset,
                                               cd->fp_chop_len,
                                               0, 0, cd->id, s->num, flags);
                            }
                            /* tell matcher we are inspecting packet */
                            s->flags |= SIG_FLAG_MPM_PACKET;
                            s->mpm_pattern_id_div_8 = cd->id / 8;
                            s->mpm_pattern_id_mod_8 = 1 << (cd->id % 8);
                            if (cd->flags & DETECT_CONTENT_NEGATED) {
                                SCLogDebug("flagging sig %"PRIu32" to be looking for negated mpm", s->id);
                                s->flags |= SIG_FLAG_MPM_PACKET_NEG;
                            }
                        }
                        if (SignatureHasStreamContent(s) &&
                            (sgh->flags & SIG_GROUP_HAVESTREAMCONTENT &&
                             !(sgh->flags & SIG_GROUP_HEAD_MPM_STREAM_COPY))) {

                            if (cd->flags & DETECT_CONTENT_NOCASE) {
                                mpm_table[sgh->mpm_ctx->mpm_type].
                                    AddPatternNocase(sgh->mpm_ctx,
                                                     cd->content + cd->fp_chop_offset,
                                                     cd->fp_chop_len,
                                                     0, 0, cd->id, s->num, flags);
                            } else {
                                mpm_table[sgh->mpm_ctx->mpm_type].
                                    AddPattern(sgh->mpm_ctx,
                                               cd->content + cd->fp_chop_offset,
                                               cd->fp_chop_len,
                                               0, 0, cd->id, s->num, flags);
                            }
                            /* tell matcher we are inspecting stream */
                            s->flags |= SIG_FLAG_MPM_STREAM;
                            s->mpm_stream_pattern_id_div_8 = cd->id / 8;
                            s->mpm_stream_pattern_id_mod_8 = 1 << (cd->id % 8);
                            if (cd->flags & DETECT_CONTENT_NEGATED) {
                                SCLogDebug("flagging sig %"PRIu32" to be looking for negated mpm", s->id);
                                s->flags |= SIG_FLAG_MPM_STREAM_NEG;
                            }
                        }

                    } else {
                        if (cd->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) {
                            if (SignatureHasPacketContent(s) &&
                                (sgh->flags & SIG_GROUP_HAVECONTENT &&
                                 !(sgh->flags & SIG_GROUP_HEAD_MPM_COPY))) {
                                cd->flags |= DETECT_CONTENT_PACKET_MPM;
                            }
                            if (SignatureHasStreamContent(s) &&
                                (sgh->flags & SIG_GROUP_HAVESTREAMCONTENT
                                 && !(sgh->flags & SIG_GROUP_HEAD_MPM_STREAM_COPY))) {
                                cd->flags |= DETECT_CONTENT_STREAM_MPM;
                            }

                            /* see if we can bypass the match validation for this pattern */
                        } else {
                            if (!(cd->flags & DETECT_CONTENT_RELATIVE_NEXT) &&
                                !(cd->flags & DETECT_CONTENT_DEPTH) &&
                                !(cd->flags & DETECT_CONTENT_OFFSET)) {

                                SigMatch *prev_sm = SigMatchGetLastSMFromLists(s, 2,
                                                                               mpm_sm->type, mpm_sm->prev);
                                if (prev_sm != NULL) {
                                    DetectContentData *prev_cd = (DetectContentData *)prev_sm->ctx;
                                    if (!(prev_cd->flags & DETECT_CONTENT_RELATIVE_NEXT)) {
                                        if (SignatureHasPacketContent(s) &&
                                            (sgh->flags & SIG_GROUP_HAVECONTENT &&
                                             !(sgh->flags & SIG_GROUP_HEAD_MPM_COPY))) {
                                            cd->flags |= DETECT_CONTENT_PACKET_MPM;
                                        }
                                        if (SignatureHasStreamContent(s) &&
                                            (sgh->flags & SIG_GROUP_HAVESTREAMCONTENT
                                             && !(sgh->flags & SIG_GROUP_HEAD_MPM_STREAM_COPY))) {
                                            cd->flags |= DETECT_CONTENT_STREAM_MPM;
                                        }
                                    }
                                } /* if (prev_sm != NULL) */
                            }
                        } /* else - if (co->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) */

                        if (SignatureHasPacketContent(s) &&
                            (sgh->flags & SIG_GROUP_HAVECONTENT &&
                             !(sgh->flags & SIG_GROUP_HEAD_MPM_COPY))) {

                            /* add the content to the "packet" mpm */
                            if (cd->flags & DETECT_CONTENT_NOCASE) {
                                mpm_table[sgh->mpm_ctx->mpm_type].
                                    AddPatternNocase(sgh->mpm_ctx,
                                                     cd->content, cd->content_len,
                                                     0, 0, cd->id, s->num, flags);
                            } else {
                                mpm_table[sgh->mpm_ctx->mpm_type].
                                    AddPattern(sgh->mpm_ctx,
                                               cd->content, cd->content_len,
                                               0, 0, cd->id, s->num, flags);
                            }
                            /* tell matcher we are inspecting packet */
                            s->flags |= SIG_FLAG_MPM_PACKET;
                            s->mpm_pattern_id_div_8 = cd->id / 8;
                            s->mpm_pattern_id_mod_8 = 1 << (cd->id % 8);
                            if (cd->flags & DETECT_CONTENT_NEGATED) {
                                SCLogDebug("flagging sig %"PRIu32" to be looking for negated mpm", s->id);
                                s->flags |= SIG_FLAG_MPM_PACKET_NEG;
                            }
                        }
                        if (SignatureHasStreamContent(s) &&
                            (sgh->flags & SIG_GROUP_HAVESTREAMCONTENT
                             && !(sgh->flags & SIG_GROUP_HEAD_MPM_STREAM_COPY))) {

                            /* add the content to the "packet" mpm */
                            if (cd->flags & DETECT_CONTENT_NOCASE) {
                                mpm_table[sgh->mpm_stream_ctx->mpm_type].
                                    AddPatternNocase(sgh->mpm_stream_ctx,
                                                     cd->content, cd->content_len,
                                                     0, 0, cd->id, s->num, flags);
                            } else {
                                mpm_table[sgh->mpm_stream_ctx->mpm_type].
                                    AddPattern(sgh->mpm_stream_ctx,
                                               cd->content, cd->content_len,
                                               0, 0, cd->id, s->num, flags);
                            }
                            /* tell matcher we are inspecting stream */
                            s->flags |= SIG_FLAG_MPM_STREAM;
                            s->mpm_stream_pattern_id_div_8 = cd->id / 8;
                            s->mpm_stream_pattern_id_mod_8 = 1 << (cd->id % 8);
                            if (cd->flags & DETECT_CONTENT_NEGATED) {
                                SCLogDebug("flagging sig %"PRIu32" to be looking for negated mpm", s->id);
                                s->flags |= SIG_FLAG_MPM_STREAM_NEG;
                            }
                        }
                    }

                    break;
                } /* case DETECT_CONTENT */
                case DETECT_URICONTENT:
                {
                    ud = (DetectContentData *)mpm_sm->ctx;
                    if (ud->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) {
                        /* add the content to the "uri" mpm */
                        if (ud->flags & DETECT_CONTENT_NOCASE) {
                            mpm_table[sgh->mpm_ctx->mpm_type].
                                AddPatternNocase(sgh->mpm_ctx,
                                                 ud->content + ud->fp_chop_offset,
                                                 ud->fp_chop_len,
                                                 0, 0, ud->id, s->num, flags);
                        } else {
                            mpm_table[sgh->mpm_ctx->mpm_type].
                                AddPattern(sgh->mpm_ctx,
                                           ud->content + ud->fp_chop_offset,
                                           ud->fp_chop_len,
                                           0, 0, ud->id, s->num, flags);
                        }
                    } else {
                        if (ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) {
                            ud->flags |= DETECT_CONTENT_URI_MPM;

                            /* see if we can bypass the match validation for this pattern */
                        } else {
                            if (!(ud->flags & DETECT_CONTENT_RELATIVE_NEXT) &&
                                !(ud->flags & DETECT_CONTENT_DEPTH) &&
                                !(ud->flags & DETECT_CONTENT_OFFSET)) {

                                SigMatch *prev_sm = SigMatchGetLastSMFromLists(s, 2,
                                                                               mpm_sm->type, mpm_sm->prev);
                                if (prev_sm != NULL) {
                                    DetectContentData *prev_ud = (DetectContentData *)prev_sm->ctx;
                                    if (!(prev_ud->flags & DETECT_CONTENT_RELATIVE_NEXT)) {
                                        ud->flags |= DETECT_CONTENT_URI_MPM;
                                    }
                                } else {
                                    ud->flags |= DETECT_CONTENT_URI_MPM;
                                }
                            }
                        } /* else - if (ud->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) */

                        /* add the content to the "packet" mpm */
                        if (ud->flags & DETECT_CONTENT_NOCASE) {
                            mpm_table[sgh->mpm_uri_ctx->mpm_type].
                                AddPatternNocase(sgh->mpm_uri_ctx,
                                                 ud->content, ud->content_len,
                                                 0, 0, ud->id, s->num, flags);
                        } else {
                            mpm_table[sgh->mpm_uri_ctx->mpm_type].
                                AddPattern(sgh->mpm_uri_ctx,
                                           ud->content, ud->content_len,
                                           0, 0, ud->id, s->num, flags);
                        }
                    }
                    /* tell matcher we are inspecting uri */
                    s->flags |= SIG_FLAG_MPM_URICONTENT;
                    s->mpm_uripattern_id = ud->id;
                    if (ud->flags & DETECT_CONTENT_NEGATED)
                        s->flags |= SIG_FLAG_MPM_URICONTENT_NEG;

                    break;
                } /* case DETECT_URICONTENT */
            } /* switch (mpm_sm->type) */

        } else {
            SCLogDebug("%"PRIu32" no mpm pattern selected", s->id);
        } /* else - if (mpm_sm != NULL) */

        return;
}

/**
 * \internal
 * \brief Helper function for PrepareGroupPopulateMpm.  Used to decide if a
 *        pattern should be skipped or considered under certain conditions.
 *
 * \param sgh Pointer to the sgh.
 * \param s   Pointer to the signature.
 * \param sm  Pointer to the SigMatch which holds the content.
 *
 * \retval 1 If the content should be skipped.
 * \retval 0 Otherwise.
 */
static int PopulateMpmSkipContent(SigGroupHead *sgh, Signature *s, SigMatch *sm)
{
    switch (sm->type) {
        case DETECT_CONTENT:
        {
            if (s->flags & SIG_FLAG_HAS_NO_PKT_AND_STREAM_CONTENT) {
                return 1;
            }

            if (!(sgh->flags & SIG_GROUP_HAVECONTENT &&
                  !(sgh->flags & SIG_GROUP_HEAD_MPM_COPY)) &&
                !(sgh->flags & SIG_GROUP_HAVESTREAMCONTENT &&
                  !(sgh->flags & SIG_GROUP_HEAD_MPM_STREAM_COPY))) {
                return 1;
            }

            DetectContentData *cd = sm->ctx;
            if (cd->flags & DETECT_CONTENT_FAST_PATTERN)
                return 0;

            if (sgh->flags & SIG_GROUP_HAVECONTENT &&
                !(sgh->flags & SIG_GROUP_HEAD_MPM_COPY) &&
                sgh->flags & SIG_GROUP_HAVESTREAMCONTENT &&
                !(sgh->flags & SIG_GROUP_HEAD_MPM_STREAM_COPY)) {
                if (sgh->mpm_content_maxlen == sgh->mpm_streamcontent_maxlen) {
                    if (cd->content_len < sgh->mpm_content_maxlen)
                        return 1;
                    else
                        return 0;
                } else if (sgh->mpm_content_maxlen < sgh->mpm_streamcontent_maxlen) {
                    if (cd->content_len < sgh->mpm_content_maxlen)
                        return 1;
                    else
                        return 0;
                } else {
                    if (cd->content_len < sgh->mpm_streamcontent_maxlen)
                        return 1;
                    else
                        return 0;
                }
            } else if (sgh->flags & SIG_GROUP_HAVECONTENT &&
                       !(sgh->flags & SIG_GROUP_HEAD_MPM_COPY)) {
                if (cd->content_len < sgh->mpm_content_maxlen)
                    return 1;
                else
                    return 0;
            } else if (sgh->flags & SIG_GROUP_HAVESTREAMCONTENT &&
                       !(sgh->flags & SIG_GROUP_HEAD_MPM_STREAM_COPY)){
                if (cd->content_len < sgh->mpm_streamcontent_maxlen)
                    return 1;
                else
                    return 0;
            }
        }

        case DETECT_URICONTENT:
        {
            if (!(sgh->flags & SIG_GROUP_HAVEURICONTENT &&
                  !(sgh->flags & SIG_GROUP_HEAD_MPM_URI_COPY))) {
                return 1;
            }

            DetectContentData *cd = sm->ctx;
            if (cd->flags & DETECT_CONTENT_FAST_PATTERN)
                return 0;

            if (cd->content_len < sgh->mpm_uricontent_maxlen)
                return 1;
            else
                return 0;
        }

        default:
            return 0;
    }

}

/**
 * \internal
 * \brief Setup the mpm content.
 *
 * \param de_ctx Pointer to the detect engine context.
 * \param sgh    Pointer to the signature group head against which we are
 *               adding patterns to the mpm ctx.
 *
 * \retval  0 Always.
 */
static int PatternMatchPreparePopulateMpm(DetectEngineCtx *de_ctx,
                                          SigGroupHead *sgh)
{
    uint32_t sig;
    uint32_t *fast_pattern = NULL;

    fast_pattern = (uint32_t *)SCMalloc(sgh->sig_cnt * sizeof(uint32_t));
    if (fast_pattern == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }
    memset(fast_pattern, 0, sgh->sig_cnt * sizeof(uint32_t));

    /* add all mpm candidates to a hash */
    for (sig = 0; sig < sgh->sig_cnt; sig++) {
        Signature *s = sgh->match_array[sig];
        if (s == NULL)
            continue;

        if (!(s->flags & SIG_FLAG_HAS_NO_PKT_AND_STREAM_CONTENT) &&
            !SignatureHasPacketContent(s) && !SignatureHasStreamContent(s)) {
            s->flags |= SIG_FLAG_HAS_NO_PKT_AND_STREAM_CONTENT;
        }

        int list_id = 0;
        for ( ; list_id < DETECT_SM_LIST_MAX; list_id++) {
            /* we have no keywords that support fp in this Signature sm list */
            if (!FastPatternSupportEnabledForSigMatchList(list_id))
                continue;

            SigMatch *sm = NULL;
            /* get the total no of patterns in this Signature, as well as find out
             * if we have a fast_pattern set in this Signature */
            for (sm = s->sm_lists[list_id]; sm != NULL; sm = sm->next) {
                /* this keyword isn't registered for fp support */
                if (!FastPatternSupportEnabledForSigMatchType(sm->type))
                    continue;

                if (PopulateMpmSkipContent(sgh, s, sm)) {
                    continue;
                }

                DetectContentData *cd = (DetectContentData *)sm->ctx;
                if (cd->flags & DETECT_CONTENT_FAST_PATTERN) {
                    fast_pattern[sig] = 1;
                    break;
                }
            } /* for (sm = s->sm_lists[list_id]; sm != NULL; sm = sm->next) */

            /* found a fast pattern for the sig.  Let's get outta here */
            if (fast_pattern[sig])
                break;
        } /* for ( ; list_id < DETECT_SM_LIST_MAX; list_id++) */
    } /* for (sig = 0; sig < sgh->sig_cnt; sig++) { */

    /* now determine which one to add to the mpm phase */
    for (sig = 0; sig < sgh->sig_cnt; sig++) {
        Signature *s = sgh->match_array[sig];
        if (s == NULL)
            continue;

        SigMatch *mpm_sm = NULL;
        SigMatch *sm = NULL;
        int list_id = 0;
        for ( ; list_id < DETECT_SM_LIST_MAX; list_id++) {
            if (!FastPatternSupportEnabledForSigMatchList(list_id))
                continue;

            for (sm = s->sm_lists[list_id]; sm != NULL; sm = sm->next) {
                if (!FastPatternSupportEnabledForSigMatchType(sm->type))
                    continue;

                /* skip in case of:
                 * 1. we expect a fastpattern but this isn't it
                 * 2. we have a smaller content than mpm_content_maxlen */
                if (fast_pattern[sig]) {
                    /* can be any content based keyword since all of them
                     * now use a unified structure - DetectContentData */
                    DetectContentData *cd = (DetectContentData *)sm->ctx;
                    if (!(cd->flags & DETECT_CONTENT_FAST_PATTERN)) {
                        SCLogDebug("not a fast pattern %"PRIu32"", cd->id);
                        continue;
                    }
                    SCLogDebug("fast pattern %"PRIu32"", cd->id);
                } else {
                    if (PopulateMpmSkipContent(sgh, s, sm)) {
                        continue;
                    }
                } /* else - if (fast_pattern[sig] == 1) */

                if (mpm_sm == NULL) {
                    mpm_sm = sm;
                    if (fast_pattern[sig])
                        break;
                } else {
                    DetectContentData *data1 = (DetectContentData *)sm->ctx;
                    DetectContentData *data2 = (DetectContentData *)mpm_sm->ctx;
                    uint32_t ls = PatternStrength(data1->content, data1->content_len);
                    uint32_t ss = PatternStrength(data2->content, data2->content_len);
                    if (ls > ss) {
                        mpm_sm = sm;
                    } else if (ls == ss) {
                        /* if 2 patterns are of equal strength, we pick the longest */
                        if (data1->content_len > data2->content_len)
                            mpm_sm = sm;
                    } else {
                        SCLogDebug("sticking with mpm_sm");
                    }
                } /* else - if (mpm == NULL) */
            } /* for (sm = s->sm_lists[list_id]; sm != NULL; sm = sm->next) */
            if (mpm_sm != NULL && fast_pattern[sig])
                break;
        } /* for ( ; list_id < DETECT_SM_LIST_MAX; list_id++) */

        PopulateMpmAddPatternToMpm(de_ctx, sgh, s, mpm_sm);
    } /* for (sig = 0; sig < sgh->sig_cnt; sig++) */

    if (fast_pattern != NULL)
        SCFree(fast_pattern);

    return 0;
}

///** \brief Setup the content portion of the sig group head */
//static int PatternMatchPreprarePopulateMpmPacket(DetectEngineCtx *de_ctx, SigGroupHead *sgh) {
//    uint32_t sig;
//    uint32_t *fast_pattern = NULL;
//
//    fast_pattern = (uint32_t *)SCMalloc(sgh->sig_cnt * sizeof(uint32_t));
//    if (fast_pattern == NULL)
//        return -1;
//    memset(fast_pattern, 0, sgh->sig_cnt * sizeof(uint32_t));
//
//    HashTable *ht = HashTableInit(4096, ContentHashFunc, ContentHashCompareFunc, ContentHashFree);
//    if (ht == NULL) {
//        SCFree(fast_pattern);
//        return -1;
//    }
//
//    /* add all the contents to a counting hash */
//    for (sig = 0; sig < sgh->sig_cnt; sig++) {
//        Signature *s = sgh->match_array[sig];
//        if (s == NULL)
//            continue;
//
//        if (SignatureHasPacketContent(s) == 0) {
//            continue;
//        }
//
//        int cnt = 0;
//        SigMatch *sm;
//
//        /* get the total no of patterns in this Signature, as well as find out
//         * if we have a fast_pattern set in this Signature */
//        for (sm = s->sm_lists[DETECT_SM_LIST_PMATCH]; sm != NULL; sm = sm->next) {
//            if (sm->type != DETECT_CONTENT)
//                continue;
//
//            DetectContentData *co = (DetectContentData *)sm->ctx;
//            if (co == NULL)
//                continue;
//
//            cnt++;
//
//            /* special handling of fast pattern keyword */
//            if (co->flags & DETECT_CONTENT_FAST_PATTERN) {
//                fast_pattern[sig] = 1;
//                SCLogDebug("sig %"PRIu32" has a fast pattern, id %"PRIu32"", s->id, co->id);
//
//                ContentHash *ch = ContentHashAlloc(co);
//                if (ch == NULL)
//                    goto error;
//
//                ContentHash *lookup_ch = (ContentHash *)HashTableLookup(ht, ch, 0);
//                if (lookup_ch == NULL) {
//                    if (HashTableAdd(ht, ch, 0) < 0)
//                        printf("Add hash failed\n");
//                } else {
//                    lookup_ch->cnt++;
//                    ContentHashFree(ch);
//                }
//            }
//        }
//
//        if (fast_pattern[sig] == 1) {
//            continue;
//        }
//
//        for (sm = s->sm_lists[DETECT_SM_LIST_PMATCH]; sm != NULL; sm = sm->next) {
//            if (sm->type != DETECT_CONTENT)
//                continue;
//
//            DetectContentData *co = (DetectContentData *)sm->ctx;
//            if (co == NULL)
//                continue;
//
//            if (co->content_len < sgh->mpm_content_maxlen) {
//                continue;
//            }
//
//            ContentHash *ch = ContentHashAlloc(co);
//            if (ch == NULL)
//                goto error;
//
//            if (cnt == 1) {
//                SCLogDebug("sig has just one pattern, so we know we will "
//                        "use it in the mpm phase.");
//                ch->use = 1;
//            }
//
//            ContentHash *lookup_ch = (ContentHash *)HashTableLookup(ht, ch, 0);
//            if (lookup_ch == NULL) {
//                int r = HashTableAdd(ht, ch, 0);
//                if (r < 0)
//                    printf("Add hash failed\n");
//            } else {
//                lookup_ch->use = ch->use;
//
//                lookup_ch->cnt++;
//                ContentHashFree(ch);
//            }
//        }
//    }
//
//    /* now determine which one to add to the mpm phase */
//    for (sig = 0; sig < sgh->sig_cnt; sig++) {
//        Signature *s = sgh->match_array[sig];
//        if (s == NULL || s->sm_lists[DETECT_SM_LIST_PMATCH] == NULL)
//            continue;
//
//        if (SignatureHasPacketContent(s) == 0) {
//            continue;
//        }
//
//        ContentHash *mpm_ch = NULL;
//        SigMatch *sm = NULL;
//
//        for (sm = s->sm_lists[DETECT_SM_LIST_PMATCH]; sm != NULL; sm = sm->next) {
//            if (sm->type != DETECT_CONTENT)
//                continue;
//
//            DetectContentData *co = (DetectContentData *)sm->ctx;
//            if (co == NULL)
//                continue;
//
//            /* skip in case of:
//             * 1. we expect a fastpattern but this isn't it
//             * 2. we have a smaller content than mpm_content_maxlen */
//            if (fast_pattern[sig] == 1) {
//                if (!(co->flags & DETECT_CONTENT_FAST_PATTERN)) {
//                    SCLogDebug("not a fast pattern %"PRIu32"", co->id);
//                    continue;
//                }
//                SCLogDebug("fast pattern %"PRIu32"", co->id);
//
//            } else if (co->content_len < sgh->mpm_content_maxlen) {
//                continue;
//            }
//
//            ContentHash *ch = ContentHashAlloc(co);
//            if (ch == NULL)
//                goto error;
//
//            ContentHash *lookup_ch = (ContentHash *)HashTableLookup(ht, ch, 0);
//            if (lookup_ch == NULL) {
//                continue;
//            }
//
//            SCLogDebug("lookup_ch->use %u, cnt %u", lookup_ch->use, lookup_ch->cnt);
//
//            if (mpm_ch == NULL) {
//                SCLogDebug("mpm_ch == NULL, so selecting lookup_ch->ptr->id %"PRIu32"", lookup_ch->ptr->id);
//                mpm_ch = lookup_ch;
//            } else {
//                uint32_t ls = PatternStrength(lookup_ch->ptr->content,lookup_ch->ptr->content_len);
//                uint32_t ss = PatternStrength(mpm_ch->ptr->content,mpm_ch->ptr->content_len);
//                if (ls > ss) {
//                    SCLogDebug("lookup_ch->ptr->id %"PRIu32" selected over %"PRIu32"", lookup_ch->ptr->id, mpm_ch->ptr->id);
//                    mpm_ch = lookup_ch;
//                }
//                else if (ls == ss) {
//                    /* if 2 patterns are of equal strength, we pick the longest */
//                    if (lookup_ch->ptr->content_len > mpm_ch->ptr->content_len) {
//                        SCLogDebug("lookup_ch->ptr->id %"PRIu32" selected over %"PRIu32" as the first is longer",
//                                lookup_ch->ptr->id, mpm_ch->ptr->id);
//                        mpm_ch = lookup_ch;
//                    }
//                } else {
//                    SCLogDebug("sticking with mpm_ch");
//                }
//            }
//
//            ContentHashFree(ch);
//        }
//
//        /* now add the mpm_ch to the mpm ctx */
//        if (mpm_ch != NULL) {
//            DetectContentData *co = mpm_ch->ptr;
//            uint16_t offset = s->flags & SIG_FLAG_RECURSIVE ? 0 : co->offset;
//            uint16_t depth = s->flags & SIG_FLAG_RECURSIVE ? 0 : co->depth;
//            offset = mpm_ch->cnt ? 0 : offset;
//            depth = mpm_ch->cnt ? 0 : depth;
//            uint8_t flags = 0;
//            char scan_negated = 0;
//
//            /* see if our content is actually negated */
//            SigMatch *tmpsm = s->sm_lists[DETECT_SM_LIST_PMATCH];
//            for ( ; tmpsm != NULL; tmpsm = tmpsm->next) {
//                if (tmpsm->type != DETECT_CONTENT)
//                    continue;
//
//                DetectContentData *tmp = (DetectContentData *)tmpsm->ctx;
//                if (tmp == NULL)
//                    continue;
//
//                if (co->id == tmp->id) {
//                    if (tmp->flags & DETECT_CONTENT_NEGATED) {
//                        scan_negated = 1;
//                    }
//                    break;
//                }
//            }
//
//            if (co->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) {
//                /* add the content to the "packet" mpm */
//                if (co->flags & DETECT_CONTENT_NOCASE) {
//                    mpm_table[sgh->mpm_ctx->mpm_type].
//                        AddPatternNocase(sgh->mpm_ctx,
//                                         co->content + co->fp_chop_offset,
//                                         co->fp_chop_len,
//                                         0, 0, co->id, s->num, flags);
//                } else {
//                    mpm_table[sgh->mpm_ctx->mpm_type].
//                        AddPattern(sgh->mpm_ctx,
//                                   co->content + co->fp_chop_offset,
//                                   co->fp_chop_len,
//                                   0, 0, co->id, s->num, flags);
//                }
//            } else {
//                if (co->flags & DETECT_CONTENT_FAST_PATTERN_ONLY) {
//                    co->avoid_double_check = 1;
//                /* see if we can bypass the match validation for this pattern */
//                } else {
//                    if (!(co->flags & DETECT_CONTENT_RELATIVE_NEXT)) {
//                        SigMatch *tmp_sm = s->sm_lists[DETECT_SM_LIST_PMATCH];
//                        for ( ; tmp_sm != NULL; tmp_sm = tmp_sm->next) {
//                            if (tmp_sm->type != DETECT_CONTENT)
//                                continue;
//
//                            DetectContentData *tmp_co = (DetectContentData *)tmpsm->ctx;
//                            if (tmp_co == NULL)
//                                continue;
//
//                            if (co->id == tmp_co->id)
//                                break;
//                        }
//
//                        SigMatch *prev_sm = SigMatchGetLastSMFromLists(s, 2,
//                                                                       DETECT_CONTENT, tmp_sm->prev);
//                        if (prev_sm != NULL) {
//                            DetectContentData *prev_co = (DetectContentData *)prev_sm->ctx;
//                            if (!(prev_co->flags & DETECT_CONTENT_RELATIVE_NEXT)) {
//                                co->avoid_double_check = 1;
//                            }
//                        }
//                    }
//                } /* else - if (co->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) */
//
//                /* add the content to the "packet" mpm */
//                if (co->flags & DETECT_CONTENT_NOCASE) {
//                    mpm_table[sgh->mpm_ctx->mpm_type].
//                        AddPatternNocase(sgh->mpm_ctx,
//                                         co->content, co->content_len,
//                                         offset, depth, co->id, s->num, flags);
//                } else {
//                    mpm_table[sgh->mpm_ctx->mpm_type].
//                        AddPattern(sgh->mpm_ctx,
//                                   co->content, co->content_len,
//                                   offset, depth, co->id, s->num, flags);
//                }
//            } /* else - if (co->flags & DETECT_CONTENT_FAST_PATTERN_CHOP) */
//
//            /* tell matcher we are inspecting packet */
//            s->flags |= SIG_FLAG_MPM_PACKET;
//
//            s->mpm_pattern_id_mod_8 = 1<<(co->id%8);
//            s->mpm_pattern_id_div_8 = co->id/8;
//            if (scan_negated) {
//                SCLogDebug("flagging sig %"PRIu32" to be looking for negated mpm", s->id);
//                s->flags |= SIG_FLAG_MPM_NEGCONTENT;
//            }
//
//            SCLogDebug("%"PRIu32" adding co->id %"PRIu32" to the mpm phase (s->num %"PRIu32")", s->id, co->id, s->num);
//        } else {
//            SCLogDebug("%"PRIu32" no mpm pattern selected", s->id);
//        }
//    }
//
//    if (fast_pattern != NULL)
//        SCFree(fast_pattern);
//
//    HashTableFree(ht);
//    return 0;
//error:
//    if (fast_pattern != NULL)
//        SCFree(fast_pattern);
//
//    if (ht != NULL)
//        HashTableFree(ht);
//    return -1;
//}
//
///** \brief Setup the content portion of the sig group head */
//static int PatternMatchPreprarePopulateMpmStream(DetectEngineCtx *de_ctx, SigGroupHead *sgh) {
//    uint32_t sig;
//    uint32_t *fast_pattern = NULL;
//
//    fast_pattern = (uint32_t *)SCMalloc(sgh->sig_cnt * sizeof(uint32_t));
//    if (fast_pattern == NULL)
//        return -1;
//    memset(fast_pattern, 0, sgh->sig_cnt * sizeof(uint32_t));
//
//    HashTable *ht = HashTableInit(4096, ContentHashFunc, ContentHashCompareFunc, ContentHashFree);
//    if (ht == NULL) {
//        SCFree(fast_pattern);
//        return -1;
//    }
//
//    /* add all the contents to a counting hash */
//    for (sig = 0; sig < sgh->sig_cnt; sig++) {
//        Signature *s = sgh->match_array[sig];
//        if (s == NULL)
//            continue;
//
//        if (SignatureHasStreamContent(s) == 0) {
//            continue;
//        }
//
//        int cnt = 0;
//        SigMatch *sm;
//
//        /* get the total no of patterns in this Signature, as well as find out
//         * if we have a fast_pattern set in this Signature */
//        for (sm = s->sm_lists[DETECT_SM_LIST_PMATCH]; sm != NULL; sm = sm->next) {
//            if (sm->type != DETECT_CONTENT)
//                continue;
//
//            DetectContentData *co = (DetectContentData *)sm->ctx;
//            if (co == NULL)
//                continue;
//
//            cnt++;
//
//            /* special handling of fast pattern keyword */
//            if (co->flags & DETECT_CONTENT_FAST_PATTERN) {
//                fast_pattern[sig] = 1;
//                SCLogDebug("sig %"PRIu32" has a fast pattern, id %"PRIu32"", s->id, co->id);
//
//                ContentHash *ch = ContentHashAlloc(co);
//                if (ch == NULL)
//                    goto error;
//
//                ContentHash *lookup_ch = (ContentHash *)HashTableLookup(ht, ch, 0);
//                if (lookup_ch == NULL) {
//                    if (HashTableAdd(ht, ch, 0) < 0)
//                        printf("Add hash failed\n");
//                } else {
//                    lookup_ch->cnt++;
//                    ContentHashFree(ch);
//                }
//            }
//        }
//
//        if (fast_pattern[sig] == 1) {
//            continue;
//        }
//
//        for (sm = s->sm_lists[DETECT_SM_LIST_PMATCH]; sm != NULL; sm = sm->next) {
//            if (sm->type != DETECT_CONTENT)
//                continue;
//
//            DetectContentData *co = (DetectContentData *)sm->ctx;
//            if (co == NULL)
//                continue;
//
//            if (co->content_len < sgh->mpm_content_maxlen) {
//                continue;
//            }
//
//            ContentHash *ch = ContentHashAlloc(co);
//            if (ch == NULL)
//                goto error;
//
//            if (cnt == 1) {
//                SCLogDebug("sig has just one pattern, so we know we will "
//                        "use it in the mpm phase.");
//                ch->use = 1;
//            }
//
//            ContentHash *lookup_ch = (ContentHash *)HashTableLookup(ht, ch, 0);
//            if (lookup_ch == NULL) {
//                int r = HashTableAdd(ht, ch, 0);
//                if (r < 0)
//                    printf("Add hash failed\n");
//            } else {
//                lookup_ch->use = ch->use;
//
//                lookup_ch->cnt++;
//                ContentHashFree(ch);
//            }
//        }
//    }
//
//    /* now determine which one to add to the mpm phase */
//    for (sig = 0; sig < sgh->sig_cnt; sig++) {
//        Signature *s = sgh->match_array[sig];
//        if (s == NULL || s->sm_lists[DETECT_SM_LIST_PMATCH] == NULL)
//            continue;
//
//        if (SignatureHasStreamContent(s) == 0) {
//            continue;
//        }
//
//        ContentHash *mpm_ch = NULL;
//        SigMatch *sm = NULL;
//
//        for (sm = s->sm_lists[DETECT_SM_LIST_PMATCH]; sm != NULL; sm = sm->next) {
//            if (sm->type != DETECT_CONTENT)
//                continue;
//
//            DetectContentData *co = (DetectContentData *)sm->ctx;
//            if (co == NULL)
//                continue;
//
//            /* skip in case of:
//             * 1. we expect a fastpattern but this isn't it
//             * 2. we have a smaller content than mpm_content_maxlen */
//            if (fast_pattern[sig] == 1) {
//                if (!(co->flags & DETECT_CONTENT_FAST_PATTERN)) {
//                    SCLogDebug("not a fast pattern %"PRIu32"", co->id);
//                    continue;
//                }
//                SCLogDebug("fast pattern %"PRIu32"", co->id);
//            } else if (co->content_len < sgh->mpm_streamcontent_maxlen) {
//                continue;
//            }
//
//            ContentHash *ch = ContentHashAlloc(co);
//            if (ch == NULL)
//                goto error;
//
//            ContentHash *lookup_ch = (ContentHash *)HashTableLookup(ht, ch, 0);
//            if (lookup_ch == NULL) {
//                continue;
//            }
//
//            SCLogDebug("lookup_ch->use %u, cnt %u", lookup_ch->use, lookup_ch->cnt);
//
//            if (mpm_ch == NULL) {
//                SCLogDebug("mpm_ch == NULL, so selecting lookup_ch->ptr->id %"PRIu32"", lookup_ch->ptr->id);
//                mpm_ch = lookup_ch;
//            } else {
//                uint32_t ls = PatternStrength(lookup_ch->ptr->content,lookup_ch->ptr->content_len);
//                uint32_t ss = PatternStrength(mpm_ch->ptr->content,mpm_ch->ptr->content_len);
//                if (ls > ss) {
//                    SCLogDebug("lookup_ch->ptr->id %"PRIu32" selected over %"PRIu32"", lookup_ch->ptr->id, mpm_ch->ptr->id);
//                    mpm_ch = lookup_ch;
//                }
//                else if (ls == ss) {
//                    /* if 2 patterns are of equal strength, we pick the longest */
//                    if (lookup_ch->ptr->content_len > mpm_ch->ptr->content_len) {
//                        SCLogDebug("lookup_ch->ptr->id %"PRIu32" selected over %"PRIu32" as the first is longer",
//                                lookup_ch->ptr->id, mpm_ch->ptr->id);
//                        mpm_ch = lookup_ch;
//                    }
//                } else {
//                    SCLogDebug("sticking with mpm_ch");
//                }
//            }
//
//            ContentHashFree(ch);
//        }
//
//        /* now add the mpm_ch to the mpm ctx */
//        if (mpm_ch != NULL) {
//            DetectContentData *co = mpm_ch->ptr;
//            uint16_t offset = s->flags & SIG_FLAG_RECURSIVE ? 0 : co->offset;
//            uint16_t depth = s->flags & SIG_FLAG_RECURSIVE ? 0 : co->depth;
//            offset = mpm_ch->cnt ? 0 : offset;
//            depth = mpm_ch->cnt ? 0 : depth;
//            uint8_t flags = 0;
//            char scan_negated = 0;
//
//            /* see if our content is actually negated */
//            SigMatch *tmpsm = s->sm_lists[DETECT_SM_LIST_PMATCH];
//            for ( ; tmpsm != NULL; tmpsm = tmpsm->next) {
//                if (tmpsm->type != DETECT_CONTENT)
//                    continue;
//
//                DetectContentData *tmp = (DetectContentData *)tmpsm->ctx;
//                if (tmp == NULL)
//                    continue;
//
//                if (co->id == tmp->id) {
//                    if (tmp->flags & DETECT_CONTENT_NEGATED) {
//                        scan_negated = 1;
//                    }
//                    break;
//                }
//            }
//
//            SCLogDebug("mpm_stream_ctx %p", sgh->mpm_stream_ctx);
//            /* add the content to the "stream" mpm */
//            if (co->flags & DETECT_CONTENT_NOCASE) {
//                mpm_table[sgh->mpm_stream_ctx->mpm_type].AddPatternNocase(sgh->mpm_stream_ctx,
//                        co->content, co->content_len, offset, depth, co->id, s->num, flags);
//            } else {
//                mpm_table[sgh->mpm_stream_ctx->mpm_type].AddPattern(sgh->mpm_stream_ctx,
//                        co->content, co->content_len, offset, depth, co->id, s->num, flags);
//            }
//
//            /* tell matcher we are inspecting stream */
//            s->flags |= SIG_FLAG_MPM_STREAM;
//
//            s->mpm_stream_pattern_id_div_8 = co->id/8;
//            s->mpm_stream_pattern_id_mod_8 = 1<<(co->id%8);
//            if (scan_negated) {
//                SCLogDebug("flagging sig %"PRIu32" to be looking for negated mpm", s->id);
//                s->flags |= SIG_FLAG_MPM_NEGCONTENT;
//            }
//
//            SCLogDebug("%"PRIu32" adding co->id %"PRIu32" to the mpm phase (s->num %"PRIu32")", s->id, co->id, s->num);
//        } else {
//            SCLogDebug("%"PRIu32" no mpm pattern selected", s->id);
//        }
//    }
//
//    if (fast_pattern != NULL)
//        SCFree(fast_pattern);
//
//    HashTableFree(ht);
//    return 0;
//error:
//    if (fast_pattern != NULL)
//        SCFree(fast_pattern);
//
//    if (ht != NULL)
//        HashTableFree(ht);
//    return -1;
//}
//
///** \brief Setup the content portion of the sig group head */
//static int PatternMatchPreprarePopulateMpmUri(DetectEngineCtx *de_ctx, SigGroupHead *sgh) {
//    uint32_t sig;
//#if 0
//    uint32_t *fast_pattern = NULL;
//    fast_pattern = (uint32_t *)SCMalloc(sgh->sig_cnt * sizeof(uint32_t));
//    if (fast_pattern == NULL)
//        return -1;
//    memset(fast_pattern, 0, sgh->sig_cnt * sizeof(uint32_t));
//#endif
//    HashTable *ht = HashTableInit(4096, UricontentHashFunc, UricontentHashCompareFunc, UricontentHashFree);
//    if (ht == NULL) {
//#if 0
//        SCFree(fast_pattern);
//#endif
//        return -1;
//    }
//
//    /* add all the contents to a counting hash */
//    for (sig = 0; sig < sgh->sig_cnt; sig++) {
//        Signature *s = sgh->match_array[sig];
//        if (s == NULL)
//            continue;
//
//        int cnt = 0;
//        SigMatch *sm;
//
//        /* get the total no of patterns in this Signature, as well as find out
//         * if we have a fast_pattern set in this Signature */
//        for (sm = s->sm_lists[DETECT_SM_LIST_UMATCH]; sm != NULL; sm = sm->next) {
//            if (sm->type != DETECT_URICONTENT)
//                continue;
//
//            DetectContentData *ud = (DetectContentData *)sm->ctx;
//            if (ud == NULL)
//                continue;
//
//            cnt++;
//#if 0
//            /* special handling of fast pattern keyword */
//            if (co->flags & DETECT_CONTENT_FAST_PATTERN) {
//                fast_pattern[sig] = 1;
//                SCLogDebug("sig %"PRIu32" has a fast pattern, id %"PRIu32"", s->id, co->id);
//
//                ContentHash *ch = ContentHashAlloc(co);
//                if (ch == NULL)
//                    goto error;
//
//                ContentHash *lookup_ch = (ContentHash *)HashTableLookup(ht, ch, 0);
//                if (lookup_ch == NULL) {
//                    if (HashTableAdd(ht, ch, 0) < 0)
//                        printf("Add hash failed\n");
//                } else {
//                    lookup_ch->cnt++;
//                    ContentHashFree(ch);
//                }
//            }
//#endif
//        }
//#if 0
//        if (fast_pattern[sig] == 1) {
//            continue;
//        }
//#endif
//        for (sm = s->sm_lists[DETECT_SM_LIST_UMATCH]; sm != NULL; sm = sm->next) {
//            if (sm->type != DETECT_URICONTENT)
//                continue;
//
//            DetectContentData *ud = (DetectContentData *)sm->ctx;
//            if (ud == NULL)
//                continue;
//
//            if (ud->content_len < sgh->mpm_uricontent_maxlen) {
//                continue;
//            }
//
//            UricontentHash *ch = UricontentHashAlloc(ud);
//            if (ch == NULL)
//                goto error;
//
//            if (cnt == 1) {
//                SCLogDebug("sig has just one pattern, so we know we will "
//                        "use it in the mpm phase.");
//                ch->use = 1;
//            }
//
//            UricontentHash *lookup_ch = (UricontentHash *)HashTableLookup(ht, ch, 0);
//            if (lookup_ch == NULL) {
//                int r = HashTableAdd(ht, ch, 0);
//                if (r < 0)
//                    printf("Add hash failed\n");
//            } else {
//                lookup_ch->use = ch->use;
//
//                lookup_ch->cnt++;
//                UricontentHashFree(ch);
//            }
//        }
//    }
//
//    /* now determine which one to add to the mpm phase */
//    for (sig = 0; sig < sgh->sig_cnt; sig++) {
//        Signature *s = sgh->match_array[sig];
//        if (s == NULL || s->sm_lists[DETECT_SM_LIST_UMATCH] == NULL)
//            continue;
//
//        UricontentHash *mpm_ch = NULL;
//        SigMatch *sm = NULL;
//
//        for (sm = s->sm_lists[DETECT_SM_LIST_UMATCH]; sm != NULL; sm = sm->next) {
//            if (sm->type != DETECT_URICONTENT)
//                continue;
//
//            DetectContentData *ud = (DetectContentData *)sm->ctx;
//            if (ud == NULL)
//                continue;
//
//            /* skip in case of:
//             * 1. we expect a fastpattern but this isn't it
//             * 2. we have a smaller content than mpm_content_maxlen */
//#if 0
//            if (fast_pattern[sig] == 1) {
//                if (!(co->flags & DETECT_CONTENT_FAST_PATTERN)) {
//                    SCLogDebug("not a fast pattern %"PRIu32"", co->id);
//                    continue;
//                }
//                SCLogDebug("fast pattern %"PRIu32"", co->id);
//
//            } else
//#endif
//            if (ud->content_len < sgh->mpm_uricontent_maxlen) {
//                continue;
//            }
//
//            UricontentHash *ch = UricontentHashAlloc(ud);
//            if (ch == NULL)
//                goto error;
//
//            UricontentHash *lookup_ch = (UricontentHash *)HashTableLookup(ht, ch, 0);
//            if (lookup_ch == NULL) {
//                continue;
//            }
//
//            SCLogDebug("lookup_ch->use %u, cnt %u", lookup_ch->use, lookup_ch->cnt);
//
//            if (mpm_ch == NULL) {
//                SCLogDebug("mpm_ch == NULL, so selecting lookup_ch->ptr->id %"PRIu32"", lookup_ch->ptr->id);
//                mpm_ch = lookup_ch;
//            } else {
//                uint32_t ls = PatternStrength(lookup_ch->ptr->content,lookup_ch->ptr->content_len);
//                uint32_t ss = PatternStrength(mpm_ch->ptr->content,mpm_ch->ptr->content_len);
//                if (ls > ss) {
//                    SCLogDebug("lookup_ch->ptr->id %"PRIu32" selected over %"PRIu32"", lookup_ch->ptr->id, mpm_ch->ptr->id);
//                    mpm_ch = lookup_ch;
//                }
//                else if (ls == ss) {
//                    /* if 2 patterns are of equal strength, we pick the longest */
//                    if (lookup_ch->ptr->content_len > mpm_ch->ptr->content_len) {
//                        SCLogDebug("lookup_ch->ptr->id %"PRIu32" selected over %"PRIu32" as the first is longer",
//                                lookup_ch->ptr->id, mpm_ch->ptr->id);
//                        mpm_ch = lookup_ch;
//                    }
//                } else {
//                    SCLogDebug("sticking with mpm_ch");
//                }
//            }
//
//            UricontentHashFree(ch);
//        }
//
//        /* now add the mpm_ch to the mpm ctx */
//        if (mpm_ch != NULL) {
//            DetectContentData *ud = mpm_ch->ptr;
//            uint8_t flags = 0;
//#if 0
//            /* see if our content is actually negated */
//            SigMatch *tmpsm = s->sm_lists[DETECT_SM_LIST_PMATCH];
//            for ( ; tmpsm != NULL; tmpsm = tmpsm->next) {
//                if (tmpsm->type != DETECT_CONTENT)
//                    continue;
//
//                DetectContentData *tmp = (DetectContentData *)tmpsm->ctx;
//                if (tmp == NULL)
//                    continue;
//
//                if (co->id == tmp->id) {
//                    if (tmp->flags & DETECT_CONTENT_NEGATED) {
//                        scan_negated = 1;
//                    }
//                    break;
//                }
//            }
//#endif
//            /* add the content to the "packet" mpm */
//            if (ud->flags & DETECT_CONTENT_NOCASE) {
//                mpm_table[sgh->mpm_uri_ctx->mpm_type].AddPatternNocase(sgh->mpm_uri_ctx,
//                        ud->content, ud->content_len, 0, 0, ud->id, s->num, flags);
//            } else {
//                mpm_table[sgh->mpm_uri_ctx->mpm_type].AddPattern(sgh->mpm_uri_ctx,
//                        ud->content, ud->content_len, 0, 0, ud->id,
//                        s->num, flags);
//            }
//
//            s->mpm_uripattern_id = ud->id;
//
//            SCLogDebug("%"PRIu32" adding ud->id %"PRIu32" to the mpm phase (s->num %"PRIu32")", s->id, ud->id, s->num);
//        } else {
//            SCLogDebug("%"PRIu32" no mpm pattern selected", s->id);
//        }
//    }
//
//#if 0
//    if (fast_pattern != NULL)
//        SCFree(fast_pattern);
//#endif
//    HashTableFree(ht);
//    return 0;
//error:
//#if 0
//    if (fast_pattern != NULL)
//        SCFree(fast_pattern);
//#endif
//    if (ht != NULL)
//        HashTableFree(ht);
//    return -1;
//}

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

        for (sm = s->sm_lists[DETECT_SM_LIST_UMATCH]; sm != NULL; sm = sm->next) {
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
        if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE) {
            sh->mpm_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx->sgh_mpm_context_packet);
        } else {
            sh->mpm_ctx = MpmFactoryGetMpmCtxForProfile(MPM_CTX_FACTORY_UNIQUE_CONTEXT);
        }

#ifndef __SC_CUDA_SUPPORT__
        MpmInitCtx(sh->mpm_ctx, de_ctx->mpm_matcher, -1);
#else
        MpmInitCtx(sh->mpm_ctx, de_ctx->mpm_matcher, de_ctx->cuda_rc_mod_handle);
#endif
    }

    if (sh->flags & SIG_GROUP_HAVESTREAMCONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_STREAM_COPY)) {
        if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE) {
            sh->mpm_stream_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx->sgh_mpm_context_stream);
        } else {
            sh->mpm_stream_ctx = MpmFactoryGetMpmCtxForProfile(MPM_CTX_FACTORY_UNIQUE_CONTEXT);
        }

#ifndef __SC_CUDA_SUPPORT__
        MpmInitCtx(sh->mpm_stream_ctx, de_ctx->mpm_matcher, -1);
#else
        MpmInitCtx(sh->mpm_stream_ctx, de_ctx->mpm_matcher, de_ctx->cuda_rc_mod_handle);
#endif
    }

    if (sh->flags & SIG_GROUP_HAVEURICONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_URI_COPY)) {
        if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_SINGLE) {
            sh->mpm_uri_ctx = MpmFactoryGetMpmCtxForProfile(de_ctx->sgh_mpm_context_uri);
        } else {
            sh->mpm_uri_ctx = MpmFactoryGetMpmCtxForProfile(MPM_CTX_FACTORY_UNIQUE_CONTEXT);
        }

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
                for (sm = s->sm_lists[DETECT_SM_LIST_PMATCH]; sm != NULL; sm = sm->next) {
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
                for (sm = s->sm_lists[DETECT_SM_LIST_PMATCH]; sm != NULL; sm = sm->next) {
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
            for (sm = s->sm_lists[DETECT_SM_LIST_UMATCH]; sm != NULL; sm = sm->next) {
                if (sm->type != DETECT_URICONTENT)
                    continue;

                DetectContentData *ud = (DetectContentData *)sm->ctx;
                if (ud == NULL)
                    continue;

                if (ud->content_len > uricontent_maxlen)
                    uricontent_maxlen = ud->content_len;

                if (uricontent_minlen == 0)
                    uricontent_minlen = ud->content_len;
                else if (ud->content_len < uricontent_minlen)
                    uricontent_minlen = ud->content_len;

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

    if ( (sh->flags & SIG_GROUP_HAVECONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_COPY)) ||
         (sh->flags & SIG_GROUP_HAVESTREAMCONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_STREAM_COPY)) ||
         (sh->flags & SIG_GROUP_HAVEURICONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_URI_COPY)) ) {

        PatternMatchPreparePopulateMpm(de_ctx, sh);

        if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL) {
            if (sh->mpm_ctx != NULL) {
                if (sh->mpm_ctx->pattern_cnt == 0) {
                    MpmFactoryReClaimMpmCtx(sh->mpm_ctx);
                    sh->mpm_ctx = NULL;
                } else {
                    if (sh->flags & SIG_GROUP_HAVECONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_COPY)) {
                        if (mpm_table[sh->mpm_ctx->mpm_type].Prepare != NULL)
                            mpm_table[sh->mpm_ctx->mpm_type].Prepare(sh->mpm_ctx);
                        }
                }
            }
            if (sh->mpm_stream_ctx != NULL) {
                if (sh->mpm_stream_ctx->pattern_cnt == 0) {
                    MpmFactoryReClaimMpmCtx(sh->mpm_stream_ctx);
                    sh->mpm_stream_ctx = NULL;
                } else {
                    if (sh->flags & SIG_GROUP_HAVESTREAMCONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_STREAM_COPY)) {
                        if (mpm_table[sh->mpm_stream_ctx->mpm_type].Prepare != NULL)
                            mpm_table[sh->mpm_stream_ctx->mpm_type].Prepare(sh->mpm_stream_ctx);
                    }
                }
            }
            if (sh->mpm_uri_ctx != NULL) {
                if (sh->mpm_uri_ctx->pattern_cnt == 0) {
                    MpmFactoryReClaimMpmCtx(sh->mpm_uri_ctx);
                    sh->mpm_uri_ctx = NULL;
                } else {
                    if (sh->flags & SIG_GROUP_HAVEURICONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_URI_COPY)) {
                        if (mpm_table[sh->mpm_uri_ctx->mpm_type].Prepare != NULL)
                            mpm_table[sh->mpm_uri_ctx->mpm_type].Prepare(sh->mpm_uri_ctx);
                    }
                }
            }
        }
    }

    ///* uricontent */
    //if (sh->flags & SIG_GROUP_HAVEURICONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_URI_COPY)) {
    //    PatternMatchPreprarePopulateMpmUri(de_ctx, sh);
    //
    //    if (mpm_table[sh->mpm_uri_ctx->mpm_type].Prepare != NULL) {
    //        if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL) {
    //            mpm_table[sh->mpm_uri_ctx->mpm_type].Prepare(sh->mpm_uri_ctx);
    //        }
    //    }
    //
    //    //sh->mpm_uri_ctx->PrintCtx(sh->mpm_uri_ctx);
    //
    //}
    //
    ///* content */
    //if (sh->flags & SIG_GROUP_HAVECONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_COPY)) {
    //    PatternMatchPreprarePopulateMpmPacket(de_ctx, sh);
    //
    //    if (mpm_table[sh->mpm_ctx->mpm_type].Prepare != NULL) {
    //        if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL) {
    //            mpm_table[sh->mpm_ctx->mpm_type].Prepare(sh->mpm_ctx);
    //        }
    //    }
    //}
    //
    ///* stream content */
    //if (sh->flags & SIG_GROUP_HAVESTREAMCONTENT && !(sh->flags & SIG_GROUP_HEAD_MPM_STREAM_COPY)) {
    //    PatternMatchPreprarePopulateMpmStream(de_ctx, sh);
    //    SCLogDebug("preparing mpm_stream_ctx %p", sh->mpm_stream_ctx);
    //    if (mpm_table[sh->mpm_stream_ctx->mpm_type].Prepare != NULL) {
    //        if (de_ctx->sgh_mpm_context == ENGINE_SGH_MPM_FACTORY_CONTEXT_FULL) {
    //            mpm_table[sh->mpm_stream_ctx->mpm_type].Prepare(sh->mpm_stream_ctx);
    //        }
    //    }
    //}

    return 0;
    //error:
    /* XXX */
    //return -1;
}

/** \brief Pattern ID Hash for sharing pattern id's
 *
 *  A per detection engine hash to make sure each pattern has a unique
 *  global id but patterns that are the same share id's.
 */
typedef struct MpmPatternIdTableElmt_ {
    uint8_t *pattern;       /**< ptr to the pattern */
    uint16_t pattern_len;   /**< pattern len */
    PatIntId id;            /**< pattern id */
    uint16_t dup_count;     /**< duplicate count */
    uint8_t sm_type;        /**< SigMatch type */
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

    if (e1->pattern_len != e2->pattern_len ||
        e1->sm_type != e2->sm_type) {
        SCReturnInt(0);
    }

    if (SCMemcmp(e1->pattern, e2->pattern, e1->pattern_len) != 0) {
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
uint32_t DetectUricontentGetId(MpmPatternIdStore *ht, DetectContentData *co) {
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
    e->sm_type = DETECT_URICONTENT;
    e->dup_count = 1;
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
        r->dup_count++;

        ht->shared_patterns++;
    }

    if (e != NULL)
        MpmPatternIdTableElmtFree(e);

    SCReturnUInt(id);
}

/**
 * \brief Get the pattern id for a for any content related keyword.
 *
 *        Supported keywords are content, http_client_body,
 *        http_method, http_uri, http_header, http_cookie.
 *
 *        Please note that you can't use it to get a pattern id for
 *        uricontent.  To retrieve a uricontent pattern id please
 *        use DetectUricontentGetId().
 *
 * \param ht   Mpm pattern id hash table store.
 * \param ctx  The keyword context.
 * \param type The SigMatch context.
 *
 * \retval id Pattern id.
 */
uint32_t DetectPatternGetId(MpmPatternIdStore *ht, void *ctx, uint8_t sm_type)
{
    SCEnter();

    MpmPatternIdTableElmt *e = NULL;
    MpmPatternIdTableElmt *r = NULL;
    PatIntId id = 0;

    e = malloc(sizeof(MpmPatternIdTableElmt));
    if (e == NULL) {
        SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
        exit(EXIT_FAILURE);
    }

    /* if uricontent had used content and content_len as its struct members
     * we wouldn't have needed this if/else here */
    if (sm_type == DETECT_URICONTENT) {
        DetectContentData *ud = ctx;
        e->pattern = SCMalloc(ud->content_len);
        if (e->pattern == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
        memcpy(e->pattern, ud->content, ud->content_len);
        e->pattern_len = ud->content_len;

        /* CONTENT, HTTP_(CLIENT_BODY|METHOD|URI|COOKIE|HEADER) */
    } else {
        DetectContentData *cd = ctx;
        e->pattern = SCMalloc(cd->content_len);
        if (e->pattern == NULL) {
            SCLogError(SC_ERR_MEM_ALLOC, "Error allocating memory");
            exit(EXIT_FAILURE);
        }
        memcpy(e->pattern, cd->content, cd->content_len);
        e->pattern_len = cd->content_len;
    }
    e->dup_count = 1;
    e->sm_type = sm_type;
    e->id = 0;

    r = HashTableLookup(ht->hash, (void *)e, sizeof(MpmPatternIdTableElmt));
    if (r == NULL) {
        /* we don't have a duplicate with this pattern + id type.  If the id is
         * for content, then it is the first entry for such a
         * pattern + id combination.  Let us create an entry for it */
        if (sm_type == DETECT_CONTENT) {
            e->id = ht->max_id;
            ht->max_id++;
            id = e->id;

            int ret = HashTableAdd(ht->hash, e, sizeof(MpmPatternIdTableElmt));
            BUG_ON(ret != 0);

            e = NULL;

            /* the id type is not content or uricontent.  It would be one of
             * those http_ modifiers against content then */
        } else {
            /* we know that this is one of those http_ modifiers against content.
             * So we would have seen a content before coming across this http_
             * modifier.  Let's retrieve this content entry that has already
             * been registered. */
            e->sm_type = DETECT_CONTENT;
            MpmPatternIdTableElmt *tmp_r = HashTableLookup(ht->hash, (void *)e, sizeof(MpmPatternIdTableElmt));
            if (tmp_r == NULL) {
                SCLogError(SC_ERR_FATAL, "How can this happen?  We have to have "
                           "a content of type DETECT_CONTENT already registered "
                           "at this point.  Impossible");
                exit(EXIT_FAILURE);
            }

            /* we have retrieved the content, and the content registered was the
             * first entry made(dup_count is 1) for that content.  Let us just
             * reset the sm_type to the http_ keyword's sm_type */
            if (tmp_r->dup_count == 1) {
                tmp_r->sm_type = sm_type;
                id = tmp_r->id;

                /* interestingly we have more than one entry for this content.
                 * Out of these tmp_r->dup_count entries, one would be for the content
                 * entry made for this http_ modifier.  Erase this entry and make
                 * a separate entry for the http_ modifier(of course with a new id) */
            } else {
                tmp_r->dup_count--;
                /* reset the sm_type, since we changed it to DETECT_CONTENT prev */
                e->sm_type = sm_type;
                e->id = ht->max_id;
                ht->max_id++;
                id = e->id;

                int ret = HashTableAdd(ht->hash, e, sizeof(MpmPatternIdTableElmt));
                BUG_ON(ret != 0);

                e = NULL;
            }
        }

        /* we do seem to have an entry for this already */
    } else {
        /* oh cool!  It is a duplicate for content, uricontent types.  Update the
         * dup_count and get out */
        if (sm_type == DETECT_CONTENT) {
            r->dup_count++;
            id = r->id;
            goto end;
        }

        /* uh oh!  a duplicate for a http_ modifier type.  Let's increase the
         * dup_count for the entry */
        r->dup_count++;
        id = r->id;

        /* let's get the content entry associated with the http keyword we are
         * currently operating on */
        e->sm_type = DETECT_CONTENT;
        MpmPatternIdTableElmt *tmp_r = HashTableLookup(ht->hash, (void *)e, sizeof(MpmPatternIdTableElmt));
        if (tmp_r == NULL) {
            SCLogError(SC_ERR_FATAL, "How can this happen?  We have to have "
                       "a content of type DETECT_CONTENT already registered "
                       "at this point.  Impossible");
            exit(EXIT_FAILURE);
        }
        /* so there are more than one content keyword entries for this pattern.
         * Reduce the dup_count */
        if (tmp_r->dup_count > 1) {
            tmp_r->dup_count--;

            /* We have just one entry.  Remove this hash table entry */
        } else {
            HashTableRemove(ht->hash, tmp_r, sizeof(MpmPatternIdTableElmt));
            ht->max_id--;
        }
    }

 end:
    if (e != NULL)
        MpmPatternIdTableElmtFree(e);

    SCReturnUInt(id);
}

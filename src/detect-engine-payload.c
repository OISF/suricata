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
 * Performs payload matching functions
 */

#include "suricata-common.h"
#include "suricata.h"

#include "decode.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-parse.h"
#include "detect-content.h"
#include "detect-pcre.h"
#include "detect-isdataat.h"
#include "detect-bytetest.h"
#include "detect-bytejump.h"
#include "detect-byte-extract.h"
#include "detect-replace.h"

#include "util-spm.h"
#include "util-spm-bm.h"
#include "util-debug.h"
#include "util-print.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

/** \brief Run the actual payload match functions
 *
 *  The follwing keywords are inspected:
 *  - content
 *  - isdaatat
 *  - pcre
 *  - bytejump
 *  - bytetest
 *
 *  All keywords are evaluated against the payload with payload_len.
 *
 *  For accounting the last match in relative matching the
 *  det_ctx->payload_offset int is used.
 *
 *  \param de_ctx Detection engine context
 *  \param det_ctx Detection engine thread context
 *  \param s Signature to inspect
 *  \param sm SigMatch to inspect
 *  \param f flow (for pcre flowvar storage)
 *  \param payload ptr to the payload to inspect
 *  \param payload_len length of the payload
 *
 *  \retval 0 no match
 *  \retval 1 match
 */
static int DoInspectPacketPayload(DetectEngineCtx *de_ctx,
                                  DetectEngineThreadCtx *det_ctx, Signature *s, SigMatch *sm,
                                  Packet *p, Flow *f, uint8_t *payload, uint32_t payload_len)
{
    SCEnter();

    det_ctx->inspection_recursion_counter++;

    if (det_ctx->inspection_recursion_counter == de_ctx->inspection_recursion_limit) {
        det_ctx->discontinue_matching = 1;
        SCReturnInt(0);
    }

    if (sm == NULL || payload_len == 0) {
        SCReturnInt(0);
    }

    switch(sm->type) {
        case DETECT_CONTENT:
        {

            DetectContentData *cd = (DetectContentData *)sm->ctx;
            SCLogDebug("inspecting content %"PRIu32" payload_len %"PRIu32, cd->id, payload_len);

            /* we might have already have this content matched by the mpm.
             * (if there is any other reason why we'd want to avoid checking
             *  it here, please fill it in) */
            //if (det_ctx->flags & DETECT_ENGINE_THREAD_CTX_INSPECTING_PACKET) {
            //    if (cd->flags & DETECT_CONTENT_PACKET_MPM && !(cd->flags & DETECT_CONTENT_NEGATED)) {
            //        /* we will remove this check in the end */
            //        if (!DETECT_CONTENT_IS_SINGLE(cd))
            //            abort();
            //        //goto match;
            //    }
            //} else if (det_ctx->flags & DETECT_ENGINE_THREAD_CTX_INSPECTING_STREAM) {
            if (det_ctx->flags & DETECT_ENGINE_THREAD_CTX_INSPECTING_STREAM) {
                if (cd->flags & DETECT_CONTENT_STREAM_MPM && !(cd->flags & DETECT_CONTENT_NEGATED)) {
                    goto match;
                }
            }

            /* rule parsers should take care of this */
#ifdef DEBUG
            BUG_ON(cd->depth != 0 && cd->depth <= cd->offset);
#endif

            /* search for our pattern, checking the matches recursively.
             * if we match we look for the next SigMatch as well */
            uint8_t *found = NULL;
            uint32_t offset = 0;
            uint32_t depth = payload_len;
            uint32_t prev_offset = 0; /**< used in recursive searching */
            uint32_t prev_payload_offset = det_ctx->payload_offset;

            do {
                if (cd->flags & DETECT_CONTENT_DISTANCE ||
                    cd->flags & DETECT_CONTENT_WITHIN) {
                    SCLogDebug("det_ctx->payload_offset %"PRIu32, det_ctx->payload_offset);

                    offset = prev_payload_offset;
                    depth = payload_len;

                    int distance = cd->distance;
                    if (cd->flags & DETECT_CONTENT_DISTANCE) {
                        if (cd->flags & DETECT_CONTENT_DISTANCE_BE) {
                            distance = det_ctx->bj_values[cd->distance];
                        }
                        if (distance < 0 && (uint32_t)(abs(distance)) > offset)
                            offset = 0;
                        else
                            offset += distance;

                        SCLogDebug("cd->distance %"PRIi32", offset %"PRIu32", depth %"PRIu32,
                            distance, offset, depth);
                    }

                    if (cd->flags & DETECT_CONTENT_WITHIN) {
                        if (cd->flags & DETECT_CONTENT_WITHIN_BE) {
                            if ((int32_t)depth > (int32_t)(prev_payload_offset + det_ctx->bj_values[cd->within] + distance)) {
                                depth = prev_payload_offset + det_ctx->bj_values[cd->within] + distance;
                            }
                        } else {
                            if ((int32_t)depth > (int32_t)(prev_payload_offset + cd->within + distance)) {
                                depth = prev_payload_offset + cd->within + distance;
                            }

                            SCLogDebug("cd->within %"PRIi32", det_ctx->payload_offset %"PRIu32", depth %"PRIu32,
                                       cd->within, prev_payload_offset, depth);
                        }
                    }

                    if (cd->flags & DETECT_CONTENT_DEPTH_BE) {
                        if ((det_ctx->bj_values[cd->depth] + prev_payload_offset) < depth) {
                            depth = prev_payload_offset + det_ctx->bj_values[cd->depth];
                        }
                    } else {
                        if (cd->depth != 0) {
                            if ((cd->depth + prev_payload_offset) < depth) {
                                depth = prev_payload_offset + cd->depth;
                            }

                            SCLogDebug("cd->depth %"PRIu32", depth %"PRIu32, cd->depth, depth);
                        }
                    }

                    if (cd->flags & DETECT_CONTENT_OFFSET_BE) {
                        if (det_ctx->bj_values[cd->offset] > offset)
                            offset = det_ctx->bj_values[cd->offset];
                    } else {
                        if (cd->offset > offset) {
                            offset = cd->offset;
                            SCLogDebug("setting offset %"PRIu32, offset);
                        }
                    }
                } else { /* implied no relative matches */
                    /* set depth */
                    if (cd->flags & DETECT_CONTENT_DEPTH_BE) {
                        depth = det_ctx->bj_values[cd->depth];
                    } else {
                        if (cd->depth != 0) {
                            depth = cd->depth;
                        }
                    }

                    /* set offset */
                    if (cd->flags & DETECT_CONTENT_OFFSET_BE)
                        offset = det_ctx->bj_values[cd->offset];
                    else
                        offset = cd->offset;
                    prev_payload_offset = 0;
                }

                /* update offset with prev_offset if we're searching for
                 * matches after the first occurence. */
                SCLogDebug("offset %"PRIu32", prev_offset %"PRIu32, offset, prev_offset);
                if (prev_offset != 0)
                    offset = prev_offset;

                SCLogDebug("offset %"PRIu32", depth %"PRIu32, offset, depth);

                if (depth > payload_len)
                    depth = payload_len;

                /* if offset is bigger than depth we can never match on a pattern.
                 * We can however, "match" on a negated pattern. */
                if (offset > depth || depth == 0) {
                    if (cd->flags & DETECT_CONTENT_NEGATED) {
                        goto match;
                    } else {
                        SCReturnInt(0);
                    }
                }

                uint8_t *spayload = payload + offset;
                uint32_t spayload_len = depth - offset;
                uint32_t match_offset = 0;
                SCLogDebug("spayload_len %"PRIu32, spayload_len);
#ifdef DEBUG
                BUG_ON(spayload_len > payload_len);
#endif

                //PrintRawDataFp(stdout,cd->content,cd->content_len);
                //PrintRawDataFp(stdout,spayload,spayload_len);

                /* \todo Add another optimization here.  If cd->content_len is
                 * greater than spayload_len found is anyways NULL */

                /* do the actual search */
                if (cd->flags & DETECT_CONTENT_NOCASE)
                    found = BoyerMooreNocase(cd->content, cd->content_len, spayload, spayload_len, cd->bm_ctx->bmGs, cd->bm_ctx->bmBc);
                else
                    found = BoyerMoore(cd->content, cd->content_len, spayload, spayload_len, cd->bm_ctx->bmGs, cd->bm_ctx->bmBc);

                /* next we evaluate the result in combination with the
                 * negation flag. */
                SCLogDebug("found %p cd negated %s", found, cd->flags & DETECT_CONTENT_NEGATED ? "true" : "false");

                if (found == NULL && !(cd->flags & DETECT_CONTENT_NEGATED)) {
                    SCReturnInt(0);
                } else if (found == NULL && cd->flags & DETECT_CONTENT_NEGATED) {
                    goto match;
                } else if (found != NULL && cd->flags & DETECT_CONTENT_NEGATED) {
                    SCLogDebug("content %"PRIu32" matched at offset %"PRIu32", but negated so no match", cd->id, match_offset);
                    /* don't bother carrying recursive matches now, for preceding
                     * relative keywords */
                    det_ctx->discontinue_matching = 1;
                    SCReturnInt(0);
                } else {
                    match_offset = (uint32_t)((found - payload) + cd->content_len);
                    SCLogDebug("content %"PRIu32" matched at offset %"PRIu32"", cd->id, match_offset);
                    det_ctx->payload_offset = match_offset;

                    /* Match branch, add replace to the list if needed */
                    if (cd->flags & DETECT_CONTENT_REPLACE) {
                        if (p) {
                            /* we will need to replace content if match is confirmed */
                            det_ctx->replist = DetectReplaceAddToList(det_ctx->replist, found, cd);
                        } else
                            SCLogWarning(SC_ERR_INVALID_VALUE, "Can't modify payload without packet");
                    }
                    if (!(cd->flags & DETECT_CONTENT_RELATIVE_NEXT)) {
                        SCLogDebug("no relative match coming up, so this is a match");
                        goto match;
                    }

                    /* bail out if we have no next match. Technically this is an
                     * error, as the current cd has the DETECT_CONTENT_RELATIVE_NEXT
                     * flag set. */
                    if (sm->next == NULL) {
                        SCReturnInt(0);
                    }

                    SCLogDebug("content %"PRIu32, cd->id);

                    /* see if the next payload keywords match. If not, we will
                     * search for another occurence of this content and see
                     * if the others match then until we run out of matches */
                    int r = DoInspectPacketPayload(de_ctx,det_ctx,s,sm->next, p, f, payload, payload_len);
                    if (r == 1) {
                        SCReturnInt(1);
                    }

                    if (det_ctx->discontinue_matching)
                        SCReturnInt(0);

                    /* set the previous match offset to the start of this match + 1 */
                    prev_offset = (match_offset - (cd->content_len - 1));
                    SCLogDebug("trying to see if there is another match after prev_offset %"PRIu32, prev_offset);
                }

            } while(1);
        }
        case DETECT_ISDATAAT:
        {
            SCLogDebug("inspecting isdataat");

            DetectIsdataatData *id = (DetectIsdataatData *)sm->ctx;
            if (id->flags & ISDATAAT_RELATIVE) {
                if (det_ctx->payload_offset + id->dataat > payload_len) {
                    SCLogDebug("det_ctx->payload_offset + id->dataat %"PRIu32" > %"PRIu32, det_ctx->payload_offset + id->dataat, payload_len);
                    if (id->flags & ISDATAAT_NEGATED)
                        goto match;
                    SCReturnInt(0);
                } else {
                    SCLogDebug("relative isdataat match");
                    if (id->flags & ISDATAAT_NEGATED)
                        SCReturnInt(0);
                    goto match;
                }
            } else {
                if (id->dataat < payload_len) {
                    SCLogDebug("absolute isdataat match");
                    if (id->flags & ISDATAAT_NEGATED)
                        SCReturnInt(0);
                    goto match;
                } else {
                    SCLogDebug("absolute isdataat mismatch, id->isdataat %"PRIu32", payload_len %"PRIu32"", id->dataat,payload_len);
                    if (id->flags & ISDATAAT_NEGATED)
                        goto match;
                    SCReturnInt(0);
                }
            }
        }
        case DETECT_PCRE:
        {
            SCLogDebug("inspecting pcre");
            DetectPcreData *pe = (DetectPcreData *)sm->ctx;
            uint32_t prev_payload_offset = det_ctx->payload_offset;
            uint32_t prev_offset = 0;
            int r = 0;

            det_ctx->pcre_match_start_offset = 0;
            do {
                r = DetectPcrePayloadMatch(det_ctx, s, sm, p, f,
                                           payload, payload_len);
                if (r == 0) {
                    det_ctx->discontinue_matching = 1;
                    SCReturnInt(0);
                }

                if (!(pe->flags & DETECT_PCRE_RELATIVE_NEXT)) {
                    SCLogDebug("no relative match coming up, so this is a match");
                    goto match;
                }

                /* save it, in case we need to do a pcre match once again */
                prev_offset = det_ctx->pcre_match_start_offset;

                /* see if the next payload keywords match. If not, we will
                 * search for another occurence of this pcre and see
                 * if the others match, until we run out of matches */
                r = DoInspectPacketPayload(de_ctx, det_ctx, s, sm->next, p,
                                           f, payload, payload_len);
                if (r == 1) {
                    SCReturnInt(1);
                }

                if (det_ctx->discontinue_matching)
                    SCReturnInt(0);

                det_ctx->payload_offset = prev_payload_offset;
                det_ctx->pcre_match_start_offset = prev_offset;
            } while (1);
        }
        case DETECT_BYTETEST:
        {
            DetectBytetestData *btd = (DetectBytetestData *)sm->ctx;
            int32_t offset = btd->offset;
            uint64_t value = btd->value;
            if (btd->flags & DETECT_BYTETEST_OFFSET_BE) {
                offset = det_ctx->bj_values[offset];
            }
            if (btd->flags & DETECT_BYTETEST_VALUE_BE) {
                value = det_ctx->bj_values[value];
            }

            if (DetectBytetestDoMatch(det_ctx,s,sm,payload,payload_len, btd->flags,
                                      offset, value) != 1) {
                SCReturnInt(0);
            }

            goto match;
        }
        case DETECT_BYTEJUMP:
        {
            DetectBytejumpData *bjd = (DetectBytejumpData *)sm->ctx;
            int32_t offset = bjd->offset;

            if (bjd->flags & DETECT_BYTEJUMP_OFFSET_BE) {
                offset = det_ctx->bj_values[offset];
            }

            if (DetectBytejumpDoMatch(det_ctx,s,sm,payload,payload_len,
                                      bjd->flags, offset) != 1) {
                SCReturnInt(0);
            }

            goto match;
        }
        case DETECT_BYTE_EXTRACT:
        {
            DetectByteExtractData *bed = (DetectByteExtractData *)sm->ctx;

            if (DetectByteExtractDoMatch(det_ctx, sm, s, payload,
                                         payload_len,
                                         &det_ctx->bj_values[bed->local_id],
                                         bed->endian) != 1) {
                SCReturnInt(0);
            }

            goto match;
        }
        /* we should never get here, but bail out just in case */
        default:
        {
            SCLogDebug("sm->type %u", sm->type);
#ifdef DEBUG
            BUG_ON(1);
#endif
        }
    }

    SCReturnInt(0);

match:
    /* this sigmatch matched, inspect the next one. If it was the last,
     * the payload portion of the signature matched. */
    if (sm->next != NULL) {
        int r = DoInspectPacketPayload(de_ctx,det_ctx,s,sm->next, p, f, payload, payload_len);
        SCReturnInt(r);
    } else {
        SCReturnInt(1);
    }
}

/**
 *  \brief Do the content inspection & validation for a signature
 *
 *  \param de_ctx Detection engine context
 *  \param det_ctx Detection engine thread context
 *  \param s Signature to inspect
 *  \param f flow (for pcre flowvar storage)
 *  \param flags app layer flags
 *  \param state App layer state
 *  \param p Packet
 *
 *  \retval 0 no match
 *  \retval 1 match
 */
int DetectEngineInspectPacketPayload(DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, Signature *s, Flow *f, uint8_t flags,
        void *alstate, Packet *p)
{
    SCEnter();
    int r = 0;

    if (s->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        SCReturnInt(0);
    }

    det_ctx->payload_offset = 0;
    det_ctx->discontinue_matching = 0;
    det_ctx->inspection_recursion_counter = 0;
    det_ctx->replist = NULL;
    //det_ctx->flags |= DETECT_ENGINE_THREAD_CTX_INSPECTING_PACKET;

    r = DoInspectPacketPayload(de_ctx, det_ctx, s, s->sm_lists[DETECT_SM_LIST_PMATCH], p, f, p->payload, p->payload_len);
    //det_ctx->flags &= ~DETECT_ENGINE_THREAD_CTX_INSPECTING_PACKET;
    if (r == 1) {
        SCReturnInt(1);
    }
    SCReturnInt(0);
}

/**
 *  \brief Do the content inspection & validation for a signature for a stream chunk
 *
 *  \param de_ctx Detection engine context
 *  \param det_ctx Detection engine thread context
 *  \param s Signature to inspect
 *  \param f flow (for pcre flowvar storage)
 *  \param payload ptr to the payload to inspect
 *  \param payload_len length of the payload
 *
 *  \retval 0 no match
 *  \retval 1 match
 *
 *  \todo we might also pass the packet to this function for the pktvar
 *        storage. Only, would that be right? We're not inspecting data
 *        from the current packet here.
 */
int DetectEngineInspectStreamPayload(DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, Signature *s, Flow *f,
        uint8_t *payload, uint32_t payload_len)
{
    SCEnter();
    int r = 0;

    if (s->sm_lists[DETECT_SM_LIST_PMATCH] == NULL) {
        SCReturnInt(0);
    }

    det_ctx->payload_offset = 0;
    det_ctx->discontinue_matching = 0;
    det_ctx->inspection_recursion_counter = 0;
    det_ctx->flags |= DETECT_ENGINE_THREAD_CTX_INSPECTING_STREAM;

    r = DoInspectPacketPayload(de_ctx, det_ctx, s, s->sm_lists[DETECT_SM_LIST_PMATCH], NULL, f, payload, payload_len);
    det_ctx->flags &= ~DETECT_ENGINE_THREAD_CTX_INSPECTING_STREAM;
    if (r == 1) {
        SCReturnInt(1);
    }

    SCReturnInt(0);
}

#ifdef UNITTESTS

/** \test Not the first but the second occurence of "abc" should be used
  *       for the 2nd match */
static int PayloadTestSig01 (void) {
    uint8_t *buf = (uint8_t *)
                    "abcabcd";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (content:\"abc\"; content:\"d\"; distance:0; within:1; sid:1;)";
    if (UTHPacketMatchSigMpm(p, sig, MPM_B2G) == 0) {
        result = 0;
        goto end;
    }

    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

/** \test Nocase matching */
static int PayloadTestSig02 (void) {
    uint8_t *buf = (uint8_t *)
                    "abcaBcd";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (content:\"abc\"; nocase; content:\"d\"; distance:0; within:1; sid:1;)";
    if (UTHPacketMatchSigMpm(p, sig, MPM_B2G) == 0) {
        result = 0;
        goto end;
    }

    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

/** \test Negative distance matching */
static int PayloadTestSig03 (void) {
    uint8_t *buf = (uint8_t *)
                    "abcaBcd";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (content:\"aBc\"; nocase; content:\"abca\"; distance:-10; within:4; sid:1;)";
    if (UTHPacketMatchSigMpm(p, sig, MPM_B2G) == 0) {
        result = 0;
        goto end;
    }

    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

/**
 * \test Test multiple relative matches.
 */
static int PayloadTestSig04(void)
{
    uint8_t *buf = (uint8_t *)"now this is is big big string now";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"this\"; content:\"is\"; within:6; content:\"big\"; within:8; "
        "content:\"string\"; within:8; sid:1;)";
    if (UTHPacketMatchSigMpm(p, sig, MPM_B2G) == 0) {
        result = 0;
        goto end;
    }

    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

/**
 * \test Test multiple relative matches.
 */
static int PayloadTestSig05(void)
{
    uint8_t *buf = (uint8_t *)"now this is is is big big big string now";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"this\"; content:\"is\"; within:9; content:\"big\"; within:12; "
        "content:\"string\"; within:8; sid:1;)";
    if (UTHPacketMatchSigMpm(p, sig, MPM_B2G) == 0) {
        result = 0;
        goto end;
    }

    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

/**
 * \test Test multiple relative matches.
 */
static int PayloadTestSig06(void)
{
    uint8_t *buf = (uint8_t *)"this this now is is     big string now";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"now\"; content:\"this\"; content:\"is\"; within:12; content:\"big\"; within:8; "
        "content:\"string\"; within:8; sid:1;)";
    if (UTHPacketMatchSigMpm(p, sig, MPM_B2G) == 0) {
        result = 0;
        goto end;
    }

    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

/**
 * \test Test multiple relative matches.
 */
static int PayloadTestSig07(void)
{
    uint8_t *buf = (uint8_t *)"         thus thus is a big";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"thus\"; offset:8; content:\"is\"; within:6; content:\"big\"; within:8; sid:1;)";

    if (UTHPacketMatchSigMpm(p, sig, MPM_B2G) == 0) {
        result = 0;
        goto end;
    }

    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

/**
 * \test Test multiple relative matches with negative matches
 *       and show the need for det_ctx->discontinue_matching.
 */
static int PayloadTestSig08(void)
{
    uint8_t *buf = (uint8_t *)"we need to fix this and yes fix this now";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"fix\"; content:\"this\"; within:6; content:!\"and\"; distance:0; sid:1;)";

    if (UTHPacketMatchSigMpm(p, sig, MPM_B2G) == 1) {
        goto end;
    }

    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

/**
 * \test Test pcre recursive matching.
 */
static int PayloadTestSig09(void)
{
    uint8_t *buf = (uint8_t *)"this is a super duper nova in super nova now";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "pcre:/super/; content:\"nova\"; within:7; sid:1;)";

    if (UTHPacketMatchSigMpm(p, sig, MPM_B2G) == 0) {
        result = 0;
        goto end;
    }

    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

/**
 * \test Test invalid sig.
 */
static int PayloadTestSig10(void)
{
    uint8_t *buf = (uint8_t *)"this is a super duper nova in super nova now";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert udp any any -> any any (msg:\"crash\"; "
        "byte_test:4,>,2,0,relative; sid:11;)";

    if (UTHPacketMatchSigMpm(p, sig, MPM_B2G) == 1) {
        result = 0;
        goto end;
    }

    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

/**
 * \test Test invalid sig.
 */
static int PayloadTestSig11(void)
{
    uint8_t *buf = (uint8_t *)"this is a super duper nova in super nova now";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert udp any any -> any any (msg:\"crash\"; "
        "byte_jump:1,0,relative; sid:11;)";

    if (UTHPacketMatchSigMpm(p, sig, MPM_B2G) == 1) {
        result = 0;
        goto end;
    }

    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

/**
 * \test Test invalid sig.
 */
static int PayloadTestSig12(void)
{
    uint8_t *buf = (uint8_t *)"this is a super duper nova in super nova now";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert udp any any -> any any (msg:\"crash\"; "
        "isdataat:10,relative; sid:11;)";

    if (UTHPacketMatchSigMpm(p, sig, MPM_B2G) == 1) {
        result = 0;
        goto end;
    }

    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

/**
 * \test Used to check the working of recursion_limit counter.
 */
static int PayloadTestSig13(void)
{
    uint8_t *buf = (uint8_t *)"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;
    uint16_t mpm_type = MPM_B2G;

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"aa\"; content:\"aa\"; distance:0; content:\"aa\"; distance:0; "
        "byte_test:1,>,200,0,relative; sid:1;)";

#include <sys/time.h>
    struct timeval tv_start, tv_end, tv_diff;

    gettimeofday(&tv_start, NULL);

    do {
        DecodeThreadVars dtv;
        ThreadVars th_v;
        DetectEngineThreadCtx *det_ctx = NULL;

        memset(&dtv, 0, sizeof(DecodeThreadVars));
        memset(&th_v, 0, sizeof(th_v));

        DetectEngineCtx *de_ctx = DetectEngineCtxInit();
        if (de_ctx == NULL) {
            printf("de_ctx == NULL: ");
            goto end;
        }
        de_ctx->inspection_recursion_limit = 3000;

        de_ctx->flags |= DE_QUIET;
        de_ctx->mpm_matcher = mpm_type;

        de_ctx->sig_list = SigInit(de_ctx, sig);
        if (de_ctx->sig_list == NULL) {
            printf("signature == NULL: ");
            goto end;
        }

        SigGroupBuild(de_ctx);
        DetectEngineThreadCtxInit(&th_v, (void *)de_ctx, (void *)&det_ctx);

        SigMatchSignatures(&th_v, de_ctx, det_ctx, p);
        if (PacketAlertCheck(p, de_ctx->sig_list->id) != 1) {
            goto end;
        }

        result = 1;
    end:
        SigGroupCleanup(de_ctx);
        SigCleanSignatures(de_ctx);

        if (det_ctx != NULL)
            DetectEngineThreadCtxDeinit(&th_v, (void *)det_ctx);

        if (de_ctx != NULL)
            DetectEngineCtxFree(de_ctx);
    } while (0);

    gettimeofday(&tv_end, NULL);

    tv_diff.tv_sec = tv_end.tv_sec - tv_start.tv_sec;
    tv_diff.tv_usec = tv_end.tv_usec - tv_start.tv_usec;

    printf("%ld.%06ld\n", tv_diff.tv_sec, tv_diff.tv_usec);

    result = 1;

    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

/**
 * \test normal & negated matching, both absolute and relative
 */
static int PayloadTestSig14(void)
{
    uint8_t *buf = (uint8_t *)"User-Agent: Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.5; en-US; rv:1.9.1b4) Gecko/20090423 Firefox/3.6 GTB5";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (content:\"User-Agent|3A| Mozilla/5.0 |28|Macintosh|3B| \"; content:\"Firefox/3.\"; distance:0; content:!\"Firefox/3.6.12\"; distance:-10; content:!\"Mozilla/5.0 |28|Macintosh|3B| U|3B| Intel Mac OS X 10.5|3B| en-US|3B| rv|3A|1.9.1b4|29| Gecko/20090423 Firefox/3.6 GTB5\"; sid:1; rev:1;)";

    //char sig[] = "alert tcp any any -> any any (content:\"User-Agent: Mozilla/5.0 (Macintosh; \"; content:\"Firefox/3.\"; distance:0; content:!\"Firefox/3.6.12\"; distance:-10; content:!\"Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10.5; en-US; rv:1.9.1b4) Gecko/20090423 Firefox/3.6 GTB5\"; sid:1; rev:1;)";

    if (UTHPacketMatchSigMpm(p, sig, MPM_B2G) == 1) {
        goto end;
    }

    result = 1;
end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

static int PayloadTestSig15(void)
{
    uint8_t *buf = (uint8_t *)"this is a super duper nova in super nova now";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"nova\"; isdataat:18,relative; sid:1;)";

    if (UTHPacketMatchSigMpm(p, sig, MPM_B2G) == 0) {
        result = 0;
        goto end;
    }

    result = 1;

end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

static int PayloadTestSig16(void)
{
    uint8_t *buf = (uint8_t *)"this is a super duper nova in super nova now";
    uint16_t buflen = strlen((char *)buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"nova\"; isdataat:!20,relative; sid:1;)";

    if (UTHPacketMatchSigMpm(p, sig, MPM_B2G) == 0) {
        result = 0;
        goto end;
    }

    result = 1;

end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

static int PayloadTestSig17(void)
{
    uint8_t buf[] = { 0xEB, 0x29, 0x25, 0x38, 0x78, 0x25, 0x38, 0x78, 0x25 };
    uint16_t buflen = 9;
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"%\"; depth:4; offset:0; "
        "content:\"%\"; within:2; distance:1; sid:1;)";

    if (UTHPacketMatchSigMpm(p, sig, MPM_B2G) == 0) {
        result = 0;
        goto end;
    }

    result = 1;

end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

static int PayloadTestSig18(void)
{
    uint8_t buf[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x35, /* the last byte is 2 */
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
        0x0E, 0x0F,
    };
    uint16_t buflen = sizeof(buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"|01 02 03 04|\"; "
        "byte_extract:1,2,one,string,dec,relative; "
        "content:\"|0C 0D 0E 0F|\"; distance:one; sid:1;)";

    if (UTHPacketMatchSigMpm(p, sig, MPM_AC) == 0) {
        result = 0;
        goto end;
    }

    result = 1;

end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

static int PayloadTestSig19(void)
{
    uint8_t buf[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x35, /* the last byte is 2 */
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
        0x0E, 0x0F,
    };
    uint16_t buflen = sizeof(buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"|01 02 03 04|\"; "
        "byte_extract:1,2,one,string,hex,relative; "
        "content:\"|0C 0D 0E 0F|\"; distance:one; sid:1;)";

    if (UTHPacketMatchSigMpm(p, sig, MPM_AC) == 0) {
        result = 0;
        goto end;
    }

    result = 1;

end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

static int PayloadTestSig20(void)
{
    uint8_t buf[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x35, /* the last byte is 2 */
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
        0x0E, 0x0F,
    };
    uint16_t buflen = sizeof(buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"|01 02 03 04|\"; "
        "byte_extract:1,2,one,string,dec,relative; "
        "content:\"|06 35 07 08|\"; offset:one; sid:1;)";

    if (UTHPacketMatchSigMpm(p, sig, MPM_AC) == 0) {
        result = 0;
        goto end;
    }

    result = 1;

end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

static int PayloadTestSig21(void)
{
    uint8_t buf[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x36, /* the last byte is 2 */
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
        0x0E, 0x0F,
    };
    uint16_t buflen = sizeof(buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"|01 02 03 04|\"; "
        "byte_extract:1,2,one,string,dec,relative; "
        "content:\"|03 04 05 06|\"; depth:one; sid:1;)";

    if (UTHPacketMatchSigMpm(p, sig, MPM_AC) == 0) {
        result = 0;
        goto end;
    }

    result = 1;

end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

static int PayloadTestSig22(void)
{
    uint8_t buf[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x36, /* the last byte is 2 */
        0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
        0x0E, 0x0F,
    };
    uint16_t buflen = sizeof(buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"|01 02 03 04|\"; "
        "byte_extract:1,2,one,string,dec,relative; "
        "content:\"|09 0A 0B 0C|\"; within:one; sid:1;)";

    if (UTHPacketMatchSigMpm(p, sig, MPM_AC) == 0) {
        result = 0;
        goto end;
    }

    result = 1;

end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

static int PayloadTestSig23(void)
{
    uint8_t buf[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x32, /* the last byte is 2 */
        0x07, 0x08, 0x09, 0x33, 0x0B, 0x0C, 0x0D,
        0x32, 0x0F,
    };
    uint16_t buflen = sizeof(buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"|01 02 03 04|\"; "
        "byte_extract:1,2,one,string,dec,relative; "
        "byte_extract:1,3,two,string,dec,relative; "
        "byte_test:1,=,one,two,string,dec,relative; sid:1;)";

    if (UTHPacketMatchSigMpm(p, sig, MPM_AC) == 0) {
        result = 0;
        goto end;
    }

    result = 1;

end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

static int PayloadTestSig24(void)
{
    uint8_t buf[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x32, /* the last byte is 2 */
        0x07, 0x08, 0x33, 0x0A, 0x0B, 0x0C, 0x0D,
        0x0E, 0x0F,
    };
    uint16_t buflen = sizeof(buf);
    Packet *p = UTHBuildPacket( buf, buflen, IPPROTO_TCP);
    int result = 0;

    char sig[] = "alert tcp any any -> any any (msg:\"dummy\"; "
        "content:\"|01 02 03 04|\"; "
        "byte_extract:1,2,one,string,dec,relative; "
        "byte_jump:1,one,string,dec,relative; "
        "content:\"|0D 0E 0F|\"; distance:0; sid:1;)";

    if (UTHPacketMatchSigMpm(p, sig, MPM_AC) == 0) {
        result = 0;
        goto end;
    }

    result = 1;

end:
    if (p != NULL)
        UTHFreePacket(p);
    return result;
}

#endif /* UNITTESTS */

void PayloadRegisterTests(void) {
#ifdef UNITTESTS
    UtRegisterTest("PayloadTestSig01", PayloadTestSig01, 1);
    UtRegisterTest("PayloadTestSig02", PayloadTestSig02, 1);
    UtRegisterTest("PayloadTestSig03", PayloadTestSig03, 1);
    UtRegisterTest("PayloadTestSig04", PayloadTestSig04, 1);
    UtRegisterTest("PayloadTestSig05", PayloadTestSig05, 1);
    UtRegisterTest("PayloadTestSig06", PayloadTestSig06, 1);
    UtRegisterTest("PayloadTestSig07", PayloadTestSig07, 1);
    UtRegisterTest("PayloadTestSig08", PayloadTestSig08, 1);
    UtRegisterTest("PayloadTestSig09", PayloadTestSig09, 1);
    UtRegisterTest("PayloadTestSig10", PayloadTestSig10, 1);
    UtRegisterTest("PayloadTestSig11", PayloadTestSig11, 1);
    UtRegisterTest("PayloadTestSig12", PayloadTestSig12, 1);
    UtRegisterTest("PayloadTestSig13", PayloadTestSig13, 1);
    UtRegisterTest("PayloadTestSig14", PayloadTestSig14, 1);
    UtRegisterTest("PayloadTestSig15", PayloadTestSig15, 1);
    UtRegisterTest("PayloadTestSig16", PayloadTestSig16, 1);
    UtRegisterTest("PayloadTestSig17", PayloadTestSig17, 1);

    UtRegisterTest("PayloadTestSig18", PayloadTestSig18, 1);
    UtRegisterTest("PayloadTestSig19", PayloadTestSig19, 1);
    UtRegisterTest("PayloadTestSig20", PayloadTestSig20, 1);
    UtRegisterTest("PayloadTestSig21", PayloadTestSig21, 1);
    UtRegisterTest("PayloadTestSig22", PayloadTestSig22, 1);
    UtRegisterTest("PayloadTestSig23", PayloadTestSig23, 1);
    UtRegisterTest("PayloadTestSig24", PayloadTestSig24, 1);
#endif /* UNITTESTS */

    return;
}

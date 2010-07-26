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
#include "detect-content.h"
#include "detect-pcre.h"
#include "detect-isdataat.h"
#include "detect-bytetest.h"
#include "detect-bytejump.h"

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

    if (sm == NULL || payload_len == 0) {
        SCReturnInt(0);
    }

    switch(sm->type) {
        case DETECT_CONTENT:
        {
            DetectContentData *cd = NULL;
            cd = (DetectContentData *)sm->ctx;
            SCLogDebug("inspecting content %"PRIu32" payload_len %"PRIu32, cd->id, payload_len);

            /* rule parsers should take care of this */
            BUG_ON(cd->depth != 0 && cd->depth <= cd->offset);

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

                    if (cd->flags & DETECT_CONTENT_DISTANCE) {
                        if (cd->distance < 0 && (uint32_t)(abs(cd->distance)) > offset)
                            offset = 0;
                        else
                            offset += cd->distance;

                        SCLogDebug("cd->distance %"PRIi32", offset %"PRIu32", depth %"PRIu32,
                            cd->distance, offset, depth);
                    }

                    if (cd->flags & DETECT_CONTENT_WITHIN) {
                        if ((int32_t)depth > (int32_t)(prev_payload_offset + cd->within)) {
                            depth = prev_payload_offset + cd->within;
                        }

                        SCLogDebug("cd->within %"PRIi32", det_ctx->payload_offset %"PRIu32", depth %"PRIu32,
                            cd->within, prev_payload_offset, depth);
                    }

                    if (cd->depth != 0) {
                        if ((cd->depth + prev_payload_offset) < depth) {
                            depth = prev_payload_offset + cd->depth;
                        }

                        SCLogDebug("cd->depth %"PRIu32", depth %"PRIu32, cd->depth, depth);
                    }

                    if (cd->offset > offset) {
                        offset = cd->offset;
                        SCLogDebug("setting offset %"PRIu32, offset);
                    }
                } else { /* implied no relative matches */
                    /* set depth */
                    if (cd->depth != 0) {
                        depth = cd->depth;
                    }

                    /* set offset */
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
                BUG_ON(spayload_len > payload_len);

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

                    if (!(cd->flags & DETECT_CONTENT_RELATIVE_NEXT)) {
                        SCLogDebug("no relative match coming up, so this is a match");
                        goto match;
                    }

                    BUG_ON(sm->next == NULL);
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
                    SCReturnInt(0);
                } else {
                    SCLogDebug("relative isdataat match");
                    goto match;
                }
            } else {
                if (id->dataat < payload_len) {
                    SCLogDebug("absolute isdataat match");
                    goto match;
                } else {
                    SCLogDebug("absolute isdataat mismatch, id->isdataat %"PRIu32", payload_len %"PRIu32"", id->dataat,payload_len);
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
            if (DetectBytetestDoMatch(det_ctx,s,sm,payload,payload_len) != 1) {
                SCReturnInt(0);
            }

            goto match;
        }
        case DETECT_BYTEJUMP:
        {
            if (DetectBytejumpDoMatch(det_ctx,s,sm,payload,payload_len) != 1) {
                SCReturnInt(0);
            }

            goto match;
        }
        /* we should never get here, but bail out just in case */
        default:
        {
            BUG_ON(1);
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

    if (s->pmatch == NULL) {
        SCReturnInt(0);
    }

    det_ctx->payload_offset = 0;
    det_ctx->discontinue_matching = 0;

    r = DoInspectPacketPayload(de_ctx, det_ctx, s, s->pmatch, p, f, p->payload, p->payload_len);
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

    if (s->pmatch == NULL) {
        SCReturnInt(0);
    }

    det_ctx->payload_offset = 0;

    r = DoInspectPacketPayload(de_ctx, det_ctx, s, s->pmatch, NULL, f, payload, payload_len);
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
        "content:this; content:is; within:6; content:big; within:8; "
        "content:string; within:8; sid:1;)";
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
        "content:this; content:is; within:9; content:big; within:12; "
        "content:string; within:8; sid:1;)";
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
        "content:now; content:this; content:is; within:12; content:big; within:8; "
        "content:string; within:8; sid:1;)";
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
        "content:thus; offset:8; content:is; within:6; content:big; within:8; sid:1;)";

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
        "content:fix; content:this; within:6; content:!\"and\"; distance:0; sid:1;)";

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
        "pcre:/super/; content:nova; within:7; sid:1;)";

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
#endif /* UNITTESTS */
}

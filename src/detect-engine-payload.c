#include "suricata-common.h"
#include "suricata.h"

#include "decode.h"

#include "detect.h"

#include "detect-content.h"
#include "detect-uricontent.h"
#include "detect-pcre.h"
#include "detect-isdataat.h"
#include "detect-bytetest.h"
#include "detect-bytejump.h"
#include "detect-http-method.h"
#include "detect-http-cookie.h"

#include "util-spm.h"
#include "util-debug.h"

/** \brief Run the actual payload match functions
 *
 *  \param de_ctx Detection engine context
 *  \param det_ctx Detection engine thread context
 *  \param s Signature to inspect
 *  \param sm SigMatch to inspect
 *  \param f Flow
 *  \param flags app layer flags
 *  \param state App layer state
 *  \param p Packet
 *  \param payload ptr to the payload to inspect
 *  \param payload_len length of the payload
 *
 *  \retval 0 no match
 *  \retval 1 match
 */
static inline int DoInspectPacketPayload(DetectEngineCtx *de_ctx,
        DetectEngineThreadCtx *det_ctx, Signature *s, SigMatch *sm, Flow *f,
        uint8_t flags, void *alstate, Packet *p, uint8_t *payload,
        uint32_t payload_len)
{
    SCEnter();

    if (sm == NULL) {
        SCReturnInt(0);
    }

    switch(sm->type) {
        case DETECT_CONTENT:
        {
            if (payload_len == 0) {
                SCReturnInt(0);
            }

            DetectContentData *cd = NULL;
            cd = (DetectContentData *)sm->ctx;
            SCLogDebug("inspecting content %"PRIu32" payload_len %"PRIu32, cd->id, payload_len);

            /* rule parsers should take care of this */
            BUG_ON(cd->depth != 0 && cd->depth <= cd->offset);

            /* search for our pattern, checking the matches recursively.
             * if we match we look for the next SigMatch as well */
            uint8_t *found = NULL;
            do {
                uint32_t offset = 0;
                uint32_t depth = payload_len;

                if (cd->flags & DETECT_CONTENT_DISTANCE ||
                    cd->flags & DETECT_CONTENT_WITHIN) {
                    SCLogDebug("det_ctx->pkt_off %"PRIu32, det_ctx->pkt_off);

                    offset = det_ctx->pkt_off;
                    depth = payload_len;

                    if (cd->flags & DETECT_CONTENT_DISTANCE) {
                        /** \todo distance can be negative */

                        offset += cd->distance;

                        SCLogDebug("cd->distance %"PRIi32", offset %"PRIu32", depth %"PRIu32,
                            cd->distance, offset, depth);
                    }

                    if (cd->flags & DETECT_CONTENT_WITHIN) {
                        if ((int32_t)depth > (int32_t)(det_ctx->pkt_off + cd->within)) {
                            depth = det_ctx->pkt_off + cd->within;
                        }

                        SCLogDebug("cd->within %"PRIi32", det_ctx->pkt_off %"PRIu32", depth %"PRIu32,
                            cd->within, det_ctx->pkt_off, depth);
                    }

                    if (cd->depth != 0) {
                        if ((cd->depth + det_ctx->pkt_off) < depth) {
                            depth = det_ctx->pkt_off + cd->depth;
                        }

                        SCLogDebug("cd->depth %"PRIu32", depth %"PRIu32, cd->depth, depth);
                    }

                    if (cd->offset > offset) {
                        offset = cd->offset;
                        SCLogDebug("setting offset %"PRIu32, offset);
                    }

                    //PrintRawDataFp(stdout,payload+offset,depth);
                } else { /* implied no relative matches */
                    /* set depth */
                    if (cd->depth != 0) {
                        depth = cd->depth;
                    }

                    /* set offset */
                    offset = cd->offset;

                    //PrintRawDataFp(stdout,payload+offset,depth);
                }

                //BUG_ON(depth == 0);
                SCLogDebug("offset %"PRIu32", depth %"PRIu32, offset, depth);

                if (depth > payload_len)
                    depth = payload_len;

                /* if offset is bigger than depth we can never match on a pattern.
                 * We can however, match on a negated pattern. */
                if (offset > depth || depth == 0) {
                    if (cd->negated == 1) {
                        goto match;
                    } else {
                        SCReturnInt(0);
                    }
                }
                //BUG_ON(offset > depth);

                uint8_t *spayload = payload + offset;
                uint32_t spayload_len = depth - offset;
                SCLogDebug("spayload_len %"PRIu32, spayload_len);
                BUG_ON(spayload_len > payload_len);

                //PrintRawDataFp(stdout,cd->content,cd->content_len);
                //PrintRawDataFp(stdout,spayload,spayload_len);

                found = BasicSearch(spayload, spayload_len, cd->content, cd->content_len);

                SCLogDebug("found %p cd->negated %d", found, cd->negated);

                if (found == NULL && cd->negated == 0) {
                    SCReturnInt(0);
                } else if (found == NULL && cd->negated == 1) {
                    goto match;
                } else if (found != NULL && cd->negated == 1) {
                    uint32_t match_offset = (uint32_t)((found - payload) + cd->content_len);
                    SCLogDebug("content %"PRIu32" matched at offset %"PRIu32", but negated so no match", cd->id, match_offset);
                    SCReturnInt(0);
                } else {
                    uint32_t match_offset = (uint32_t)((found - payload) + cd->content_len);
                    SCLogDebug("content %"PRIu32" matched at offset %"PRIu32"", cd->id, match_offset);
                    det_ctx->pkt_off = match_offset;

                    if (cd->flags & DETECT_CONTENT_ISDATAAT_RELATIVE) {
                        if (det_ctx->pkt_off + cd->isdataat > payload_len) {
                            SCLogDebug("det_ctx->pkt_off + cd->isdataat %"PRIu32" > %"PRIu32, det_ctx->pkt_off + cd->isdataat, payload_len);
                            SCReturnInt(0);
                        } else {
                            SCLogDebug("relative isdataat match");
                        }
                    }
                }

                SCLogDebug("content %"PRIu32", next? %s", cd->id, sm->next?"true":"false");

                goto match;
            } while(1);
        }
        case DETECT_ISDATAAT:
        {
            SCLogDebug("inspecting isdataat");

            DetectIsdataatData *id = (DetectIsdataatData *)sm->ctx;
            BUG_ON(id->flags & ISDATAAT_RELATIVE);

            if (id->dataat < payload_len) {
                SCLogDebug("absolute isdataat match");
                goto match;
            } else {
                SCLogDebug("absolute isdataat mismatch, id->isdataat %"PRIu32", payload_len %"PRIu32"", id->dataat,payload_len);
                SCReturnInt(0);
            }
        }
        case DETECT_PCRE:
        {
            SCLogDebug("inspecting pcre");

            /** \todo consider ptrs */
            int r = DetectPcreDoMatch(det_ctx, p, s, sm);
            if (r == 1) {
                goto match;
            }

            SCReturnInt(0);
        }
        case DETECT_PCRE_HTTPBODY:
        {
            SCLogDebug("inspecting pcre http body");
            int r = DetectPcreALDoMatch(det_ctx, s, sm, f, flags, alstate);
            if (r != 1) {
                SCReturnInt(0);
            }

            goto match;
        }
        case DETECT_AL_HTTP_COOKIE:
        {
            int r = DetectHttpCookieDoMatch(det_ctx, s, sm, f, flags, alstate);
            if (r != 1) {
                SCReturnInt(0);
            }

            goto match;
        }
        case DETECT_AL_HTTP_METHOD:
        {
            int r = DetectHttpMethodDoMatch(det_ctx, s, sm, f, flags, alstate);
            if (r != 1) {
                SCReturnInt(0);
            }

            goto match;
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
        /* assume unsupported matches match */
        default:
        {
            SCLogDebug("inspecting default, match assumed");

            goto match;
        }
    }

    SCReturnInt(0);
match:
    if (sm->next != NULL) {
        int r = DoInspectPacketPayload(de_ctx,det_ctx,s,sm->next, f, flags, alstate, p, payload, payload_len);
        SCReturnInt(r);
    } else {
        SCReturnInt(1);
    }
}

/** \brief Do the content inspection for a signature
 *
 *  \param de_ctx Detection engine context
 *  \param det_ctx Detection engine thread context
 *  \param s Signature to inspect
 *  \param sm SigMatch to inspect
 *  \param f Flow
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

    det_ctx->pkt_off = 0;

    r = DoInspectPacketPayload(de_ctx, det_ctx, s, s->pmatch, f, flags, alstate, p, p->payload, p->payload_len);
    if (r == 1) {
        SCReturnInt(1);
    }

    SCReturnInt(0);
}


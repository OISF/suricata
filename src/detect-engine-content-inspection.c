/* Copyright (C) 2007-2023 Open Information Security Foundation
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
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 *
 * Performs content inspection on any buffer supplied.
 */

#include "suricata-common.h"
#include "suricata.h"
#include "decode.h"

#include "detect.h"
#include "detect-engine.h"
#include "detect-parse.h"

#include "rust.h"

#include "detect-asn1.h"
#include "detect-content.h"
#include "detect-pcre.h"
#include "detect-isdataat.h"
#include "detect-bytetest.h"
#include "detect-bytemath.h"
#include "detect-bytejump.h"
#include "detect-byte-extract.h"
#include "detect-replace.h"
#include "detect-engine-content-inspection.h"
#include "detect-uricontent.h"
#include "detect-urilen.h"
#include "detect-engine-uint.h"
#include "detect-bsize.h"
#include "detect-lua.h"
#include "detect-base64-decode.h"
#include "detect-base64-data.h"
#include "detect-dataset.h"
#include "detect-datarep.h"

#include "util-spm.h"
#include "util-debug.h"
#include "util-print.h"
#include "util-validate.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "util-profiling.h"

#include "util-lua.h"

#ifdef UNITTESTS
thread_local uint32_t ut_inspection_recursion_counter = 0;
#endif

struct DetectEngineContentInspectionCtx {
    struct {
        uint32_t count;
        const uint32_t limit;
    } recursion;
};

/**
 * \brief Run the actual payload match functions
 *
 * All keywords are evaluated against the buffer with buffer_len.
 *
 * For accounting the last match in relative matching the
 * det_ctx->buffer_offset int is used.
 *
 * \param det_ctx         Detection engine thread context
 * \param s               Signature to inspect
 * \param sm              SigMatch to inspect
 * \param p               Packet. Can be NULL.
 * \param f               Flow (for pcre flowvar storage)
 * \param buffer          Ptr to the buffer to inspect
 * \param buffer_len      Length of the payload
 * \param stream_start_offset Indicates the start of the current buffer in
 *                            the whole buffer stream inspected.  This
 *                            applies if the current buffer is inspected
 *                            in chunks.
 * \param inspection_mode Refers to the engine inspection mode we are currently
 *                        inspecting.  Can be payload, stream, one of the http
 *                        buffer inspection modes or dce inspection mode.
 * \param flags           DETECT_CI_FLAG_*
 *
 *  \retval -1 no match and give up (discontinue matching)
 *  \retval 0 no match
 *  \retval 1 match
 */
static int DetectEngineContentInspectionInternal(DetectEngineThreadCtx *det_ctx,
        struct DetectEngineContentInspectionCtx *ctx, const Signature *s, const SigMatchData *smd,
        Packet *p, Flow *f, const uint8_t *buffer, const uint32_t buffer_len,
        const uint32_t stream_start_offset, const uint8_t flags,
        const enum DetectContentInspectionType inspection_mode)
{
    SCEnter();
    KEYWORD_PROFILING_START;

    ctx->recursion.count++;
    if (unlikely(ctx->recursion.count == ctx->recursion.limit)) {
        KEYWORD_PROFILING_END(det_ctx, smd->type, 0);
        SCReturnInt(-1);
    }

    // we want the ability to match on bsize: 0
    if (smd == NULL || buffer == NULL) {
        KEYWORD_PROFILING_END(det_ctx, smd->type, 0);
        SCReturnInt(0);
    }

    if (smd->type == DETECT_CONTENT) {
        const DetectContentData *cd = (const DetectContentData *)smd->ctx;
        SCLogDebug("inspecting content %"PRIu32" buffer_len %"PRIu32, cd->id, buffer_len);

        /* we might have already have this content matched by the mpm.
         * (if there is any other reason why we'd want to avoid checking
         *  it here, please fill it in) */
        //if (cd->flags & DETECT_CONTENT_NO_DOUBLE_INSPECTION_REQUIRED) {
        //    goto match;
        //}

        /* rule parsers should take care of this */
#ifdef DEBUG
        BUG_ON(cd->depth != 0 && cd->depth <= cd->offset);
#endif

        /* search for our pattern, checking the matches recursively.
         * if we match we look for the next SigMatch as well */
        uint32_t prev_offset = 0; /**< used in recursive searching */
        uint32_t prev_buffer_offset = det_ctx->buffer_offset;

        do {
            uint32_t depth = buffer_len;
            uint32_t offset = 0;
            if ((cd->flags & DETECT_CONTENT_DISTANCE) ||
                (cd->flags & DETECT_CONTENT_WITHIN)) {
                SCLogDebug("det_ctx->buffer_offset %" PRIu32, det_ctx->buffer_offset);
                offset = prev_buffer_offset;

                int distance = cd->distance;
                if (cd->flags & DETECT_CONTENT_DISTANCE) {
                    if (cd->flags & DETECT_CONTENT_DISTANCE_VAR) {
                        distance = det_ctx->byte_values[cd->distance];
                    }
                    if (distance < 0 && (uint32_t)(abs(distance)) > offset)
                        offset = 0;
                    else
                        offset += distance;

                    SCLogDebug("cd->distance %"PRIi32", offset %"PRIu32", depth %"PRIu32,
                               distance, offset, depth);
                }

                if (cd->flags & DETECT_CONTENT_WITHIN) {
                    if (cd->flags & DETECT_CONTENT_WITHIN_VAR) {
                        if ((int32_t)depth > (int32_t)(prev_buffer_offset + det_ctx->byte_values[cd->within] + distance)) {
                            depth = prev_buffer_offset + det_ctx->byte_values[cd->within] + distance;
                        }
                    } else {
                        if ((int32_t)depth > (int32_t)(prev_buffer_offset + cd->within + distance)) {
                            depth = prev_buffer_offset + cd->within + distance;
                        }

                        SCLogDebug("cd->within %"PRIi32", det_ctx->buffer_offset %"PRIu32", depth %"PRIu32,
                                   cd->within, prev_buffer_offset, depth);
                    }

                    if (stream_start_offset != 0 && prev_buffer_offset == 0) {
                        if (depth <= stream_start_offset) {
                            goto no_match;
                        } else if (depth >= (stream_start_offset + buffer_len)) {
                            ;
                        } else {
                            depth = depth - stream_start_offset;
                        }
                    }
                }

                if (cd->flags & DETECT_CONTENT_DEPTH_VAR) {
                    if ((det_ctx->byte_values[cd->depth] + prev_buffer_offset) < depth) {
                        depth = prev_buffer_offset + det_ctx->byte_values[cd->depth];
                    }
                } else {
                    if (cd->depth != 0) {
                        if ((cd->depth + prev_buffer_offset) < depth) {
                            depth = prev_buffer_offset + cd->depth;
                        }

                        SCLogDebug("cd->depth %"PRIu32", depth %"PRIu32, cd->depth, depth);
                    }
                }

                if (cd->flags & DETECT_CONTENT_OFFSET_VAR) {
                    if (det_ctx->byte_values[cd->offset] > offset)
                        offset = det_ctx->byte_values[cd->offset];
                } else {
                    if (cd->offset > offset) {
                        offset = cd->offset;
                        SCLogDebug("setting offset %"PRIu32, offset);
                    }
                }
            } else { /* implied no relative matches */
                /* set depth */
                if (cd->flags & DETECT_CONTENT_DEPTH_VAR) {
                    depth = det_ctx->byte_values[cd->depth];
                } else {
                    if (cd->depth != 0) {
                        depth = cd->depth;
                    }
                }

                if (stream_start_offset != 0 && cd->flags & DETECT_CONTENT_DEPTH) {
                    if (depth <= stream_start_offset) {
                        goto no_match;
                    } else if (depth >= (stream_start_offset + buffer_len)) {
                        ;
                    } else {
                        depth = depth - stream_start_offset;
                    }
                }

                /* set offset */
                if (cd->flags & DETECT_CONTENT_OFFSET_VAR)
                    offset = det_ctx->byte_values[cd->offset];
                else
                    offset = cd->offset;
                prev_buffer_offset = 0;
            }

            /* If the value came from a variable, make sure to adjust the depth so it's relative
             * to the offset value.
             */
            if (cd->flags & (DETECT_CONTENT_DISTANCE_VAR|DETECT_CONTENT_OFFSET_VAR|DETECT_CONTENT_DEPTH_VAR)) {
                 depth += offset;
            }

            /* update offset with prev_offset if we're searching for
             * matches after the first occurrence. */
            SCLogDebug("offset %"PRIu32", prev_offset %"PRIu32, offset, prev_offset);
            if (prev_offset != 0)
                offset = prev_offset;

            SCLogDebug("offset %"PRIu32", depth %"PRIu32, offset, depth);

            if (depth > buffer_len)
                depth = buffer_len;

            /* if offset is bigger than depth we can never match on a pattern.
             * We can however, "match" on a negated pattern. */
            if (offset > depth || depth == 0) {
                if (cd->flags & DETECT_CONTENT_NEGATED) {
                    goto match;
                } else {
                    goto no_match;
                }
            }

            const uint8_t *sbuffer = buffer + offset;
            uint32_t sbuffer_len = depth - offset;
            SCLogDebug("sbuffer_len %" PRIu32 " depth: %" PRIu32 ", buffer_len: %" PRIu32,
                    sbuffer_len, depth, buffer_len);
#ifdef DEBUG
            BUG_ON(sbuffer_len > buffer_len);
#endif
            const uint8_t *found;
            if (cd->flags & DETECT_CONTENT_ENDS_WITH && depth < buffer_len) {
                SCLogDebug("depth < buffer_len while DETECT_CONTENT_ENDS_WITH is set. Can't possibly match.");
                found = NULL;
            } else if (cd->content_len > sbuffer_len) {
                found = NULL;
            } else {
                /* do the actual search */
                found = SpmScan(cd->spm_ctx, det_ctx->spm_thread_ctx, sbuffer,
                        sbuffer_len);
            }

            /* next we evaluate the result in combination with the
             * negation flag. */
            SCLogDebug("found %p cd negated %s", found, cd->flags & DETECT_CONTENT_NEGATED ? "true" : "false");

            if (found == NULL) {
                if (!(cd->flags & DETECT_CONTENT_NEGATED)) {
                    if ((cd->flags & (DETECT_CONTENT_DISTANCE | DETECT_CONTENT_WITHIN)) == 0) {
                        /* independent match from previous matches, so failure is fatal */
                        goto no_match_discontinue;
                    }

                    goto no_match;
                } else {
                    goto match;
                }
            }

            uint32_t match_offset = (uint32_t)((found - buffer) + cd->content_len);
            if (cd->flags & DETECT_CONTENT_NEGATED) {
                SCLogDebug("content %" PRIu32 " matched at offset %" PRIu32
                           ", but negated so no match",
                        cd->id, match_offset);
                /* don't bother carrying recursive matches now, for preceding
                 * relative keywords */

                /* found a match but not at the end of the buffer */
                if (cd->flags & DETECT_CONTENT_ENDS_WITH) {
                    if (sbuffer_len != match_offset) {
                        SCLogDebug("content \"%s\" %" PRIu32 " matched at offset %" PRIu32
                                   ", but not at end of buffer so match",
                                cd->content, cd->id, match_offset);
                        goto match;
                    }
                }
                if (DETECT_CONTENT_IS_SINGLE(cd)) {
                    goto no_match_discontinue;
                }
                goto no_match;
            }

            SCLogDebug("content %" PRIu32 " matched at offset %" PRIu32 "", cd->id, match_offset);
            det_ctx->buffer_offset = match_offset;

            if ((cd->flags & DETECT_CONTENT_ENDS_WITH) == 0 || match_offset == buffer_len) {
                /* Match branch, add replace to the list if needed */
                if (unlikely(cd->flags & DETECT_CONTENT_REPLACE)) {
                    if (inspection_mode == DETECT_ENGINE_CONTENT_INSPECTION_MODE_PAYLOAD) {
                        /* we will need to replace content if match is confirmed
                         * cast to non-const as replace writes to it. */
                        det_ctx->replist =
                                DetectReplaceAddToList(det_ctx->replist, (uint8_t *)found, cd);
                    } else {
                        SCLogWarning("Can't modify payload without packet");
                    }
                }

                /* if this is the last match we're done */
                if (smd->is_last) {
                    goto match;
                }

                SCLogDebug("content %" PRIu32, cd->id);
                KEYWORD_PROFILING_END(det_ctx, smd->type, 1);

                /* see if the next buffer keywords match. If not, we will
                 * search for another occurrence of this content and see
                 * if the others match then until we run out of matches */
                int r = DetectEngineContentInspectionInternal(det_ctx, ctx, s, smd + 1, p, f,
                        buffer, buffer_len, stream_start_offset, flags, inspection_mode);
                if (r == 1) {
                    SCReturnInt(1);
                } else if (r == -1) {
                    SCLogDebug("'next sm' said to discontinue this right now");
                    SCReturnInt(-1);
                }
                SCLogDebug("no match for 'next sm'");

                /* no match and no reason to look for another instance */
                if ((cd->flags & DETECT_CONTENT_WITHIN_NEXT) == 0) {
                    SCLogDebug("'next sm' does not depend on me, so we can give up");
                    SCReturnInt(-1);
                }

                SCLogDebug("'next sm' depends on me %p, lets see what we can do (flags %u)", cd,
                        cd->flags);
            }
            /* set the previous match offset to the start of this match + 1 */
            prev_offset = (match_offset - (cd->content_len - 1));
            SCLogDebug("trying to see if there is another match after prev_offset %" PRIu32,
                    prev_offset);
        } while(1);

    } else if (smd->type == DETECT_ABSENT) {
        const DetectAbsentData *id = (DetectAbsentData *)smd->ctx;
        if (!id->or_else) {
            // we match only on absent buffer
            goto no_match;
        }
        goto match;
    } else if (smd->type == DETECT_ISDATAAT) {
        SCLogDebug("inspecting isdataat");

        const DetectIsdataatData *id = (DetectIsdataatData *)smd->ctx;
        uint32_t dataat = id->dataat;
        if (id->flags & ISDATAAT_OFFSET_VAR) {
            uint64_t be_value = det_ctx->byte_values[dataat];
            if (be_value >= 100000000) {
                if ((id->flags & ISDATAAT_NEGATED) == 0) {
                    SCLogDebug("extracted value %"PRIu64" very big: no match", be_value);
                    goto no_match;
                }
                SCLogDebug("extracted value way %"PRIu64" very big: match", be_value);
                goto match;
            }
            dataat = (uint32_t)be_value;
            SCLogDebug("isdataat: using value %u from byte_extract local_id %u", dataat, id->dataat);
        }

        if (id->flags & ISDATAAT_RELATIVE) {
            if (det_ctx->buffer_offset + dataat > buffer_len) {
                SCLogDebug("det_ctx->buffer_offset + dataat %"PRIu32" > %"PRIu32, det_ctx->buffer_offset + dataat, buffer_len);
                if (id->flags & ISDATAAT_NEGATED)
                    goto match;
                if ((id->flags & ISDATAAT_OFFSET_VAR) == 0) {
                    goto no_match_discontinue;
                }
                goto no_match;
            } else {
                SCLogDebug("relative isdataat match");
                if (id->flags & ISDATAAT_NEGATED) {
                    goto no_match;
                }
                goto match;
            }
        } else {
            if (dataat < buffer_len) {
                SCLogDebug("absolute isdataat match");
                if (id->flags & ISDATAAT_NEGATED) {
                    if ((id->flags & ISDATAAT_OFFSET_VAR) == 0) {
                        goto no_match_discontinue;
                    }
                    goto no_match;
                }
                goto match;
            } else {
                SCLogDebug("absolute isdataat mismatch, id->isdataat %"PRIu32", buffer_len %"PRIu32"", dataat, buffer_len);
                if (id->flags & ISDATAAT_NEGATED)
                    goto match;
                if ((id->flags & ISDATAAT_OFFSET_VAR) == 0) {
                    goto no_match_discontinue;
                }
                goto no_match;
            }
        }

    } else if (smd->type == DETECT_PCRE) {
        SCLogDebug("inspecting pcre");
        const DetectPcreData *pe = (const DetectPcreData *)smd->ctx;
        uint32_t prev_buffer_offset = det_ctx->buffer_offset;
        uint32_t prev_offset = 0;

        det_ctx->pcre_match_start_offset = 0;
        do {
            int r = DetectPcrePayloadMatch(det_ctx, s, smd, p, f, buffer, buffer_len);
            if (r == 0) {
                goto no_match;
            }

            if (!(pe->flags & DETECT_PCRE_RELATIVE_NEXT)) {
                SCLogDebug("no relative match coming up, so this is a match");
                goto match;
            }
            KEYWORD_PROFILING_END(det_ctx, smd->type, 1);

            /* save it, in case we need to do a pcre match once again */
            prev_offset = det_ctx->pcre_match_start_offset;

            /* see if the next payload keywords match. If not, we will
             * search for another occurrence of this pcre and see
             * if the others match, until we run out of matches */
            r = DetectEngineContentInspectionInternal(det_ctx, ctx, s, smd + 1, p, f, buffer,
                    buffer_len, stream_start_offset, flags, inspection_mode);
            if (r == 1) {
                SCReturnInt(1);
            } else if (r == -1) {
                SCReturnInt(-1);
            }

            det_ctx->buffer_offset = prev_buffer_offset;
            det_ctx->pcre_match_start_offset = prev_offset;
        } while (1);

    } else if (smd->type == DETECT_BYTETEST) {
        const DetectBytetestData *btd = (const DetectBytetestData *)smd->ctx;
        uint16_t btflags = btd->flags;
        int32_t offset = btd->offset;
        uint64_t value = btd->value;
        int32_t nbytes = btd->nbytes;
        if (btflags & DETECT_BYTETEST_OFFSET_VAR) {
            offset = det_ctx->byte_values[offset];
        }
        if (btflags & DETECT_BYTETEST_VALUE_VAR) {
            value = det_ctx->byte_values[value];
        }
        if (btflags & DETECT_BYTETEST_NBYTES_VAR) {
            nbytes = det_ctx->byte_values[nbytes];
        }

        /* if we have dce enabled we will have to use the endianness
         * specified by the dce header */
        if (btflags & DETECT_BYTETEST_DCE) {
            /* enable the endianness flag temporarily.  once we are done
             * processing we reset the flags to the original value*/
            btflags |= ((flags & DETECT_CI_FLAGS_DCE_LE) ?
                      DETECT_BYTETEST_LITTLE: 0);
        }

        if (DetectBytetestDoMatch(det_ctx, s, smd->ctx, buffer, buffer_len, btflags, offset, nbytes,
                    value) != 1) {
            goto no_match;
        }

        goto match;

    } else if (smd->type == DETECT_BYTEJUMP) {
        const DetectBytejumpData *bjd = (const DetectBytejumpData *)smd->ctx;
        uint16_t bjflags = bjd->flags;
        int32_t offset = bjd->offset;
        int32_t nbytes;

        if (bjflags & DETECT_BYTEJUMP_OFFSET_VAR) {
            offset = det_ctx->byte_values[offset];
        }

        if (bjflags & DETECT_BYTEJUMP_NBYTES_VAR) {
            nbytes = det_ctx->byte_values[bjd->nbytes];
        } else {
            nbytes = bjd->nbytes;
        }

        /* if we have dce enabled we will have to use the endianness
         * specified by the dce header */
        if (bjflags & DETECT_BYTEJUMP_DCE) {
            /* enable the endianness flag temporarily.  once we are done
             * processing we reset the flags to the original value*/
            bjflags |= ((flags & DETECT_CI_FLAGS_DCE_LE) ?
                      DETECT_BYTEJUMP_LITTLE: 0);
        }

        if (!DetectBytejumpDoMatch(
                    det_ctx, s, smd->ctx, buffer, buffer_len, bjflags, nbytes, offset)) {
            goto no_match;
        }

        goto match;

    } else if (smd->type == DETECT_BYTE_EXTRACT) {

        const SCDetectByteExtractData *bed = (const SCDetectByteExtractData *)smd->ctx;
        uint8_t endian = bed->endian;

        /* if we have dce enabled we will have to use the endianness
         * specified by the dce header */
        if ((bed->flags & DETECT_BYTE_EXTRACT_FLAG_ENDIAN) && endian == EndianDCE &&
                flags & (DETECT_CI_FLAGS_DCE_LE | DETECT_CI_FLAGS_DCE_BE)) {

            /* enable the endianness flag temporarily.  once we are done
             * processing we reset the flags to the original value*/
            endian |= ((flags & DETECT_CI_FLAGS_DCE_LE) ? LittleEndian : BigEndian);
        }

        if (DetectByteExtractDoMatch(det_ctx, smd, s, buffer, buffer_len,
                    &det_ctx->byte_values[bed->local_id], endian) != 1) {
            goto no_match;
        }

        SCLogDebug("[BE] Fetched value for index %d: %"PRIu64,
                   bed->local_id, det_ctx->byte_values[bed->local_id]);
        goto match;

    } else if (smd->type == DETECT_BYTEMATH) {

        const DetectByteMathData *bmd = (const DetectByteMathData *)smd->ctx;
        uint8_t endian = bmd->endian;

        /* if we have dce enabled we will have to use the endianness
         * specified by the dce header */
        if ((bmd->flags & DETECT_BYTEMATH_FLAG_ENDIAN) && endian == (int)EndianDCE &&
                flags & (DETECT_CI_FLAGS_DCE_LE | DETECT_CI_FLAGS_DCE_BE)) {
            /* enable the endianness flag temporarily.  once we are done
             * processing we reset the flags to the original value*/
            endian = (uint8_t)((flags & DETECT_CI_FLAGS_DCE_LE) ? LittleEndian : BigEndian);
        }
        uint64_t rvalue;
        if (bmd->flags & DETECT_BYTEMATH_FLAG_RVALUE_VAR) {
            rvalue = det_ctx->byte_values[bmd->rvalue];
        } else {
            rvalue = bmd->rvalue;
        }

        uint8_t nbytes;
        if (bmd->flags & DETECT_BYTEMATH_FLAG_NBYTES_VAR) {
            nbytes = (uint8_t)det_ctx->byte_values[bmd->nbytes];
        } else {
            nbytes = bmd->nbytes;
        }

        if (DetectByteMathDoMatch(det_ctx, bmd, s, buffer, buffer_len, nbytes, rvalue,
                    &det_ctx->byte_values[bmd->local_id], endian) != 1) {
            goto no_match;
        }

        SCLogDebug("[BM] Fetched value for index %d: %"PRIu64,
                   bmd->local_id, det_ctx->byte_values[bmd->local_id]);
        goto match;

    } else if (smd->type == DETECT_BSIZE) {

        const bool eof = (flags & DETECT_CI_FLAGS_END);
        const uint64_t data_size = buffer_len + stream_start_offset;
        int r = DetectBsizeMatch(smd->ctx, data_size, eof);
        if (r < 0) {
            goto no_match_discontinue;
        } else if (r == 0) {
            goto no_match;
        }
        goto match;

    } else if (smd->type == DETECT_DATASET) {

        //PrintRawDataFp(stdout, buffer, buffer_len);
        const DetectDatasetData *sd = (const DetectDatasetData *) smd->ctx;
        int r = DetectDatasetBufferMatch(det_ctx, sd, buffer, buffer_len); //TODO buffer offset?
        if (r == 1) {
            goto match;
        }
        goto no_match_discontinue;

    } else if (smd->type == DETECT_DATAREP) {

        //PrintRawDataFp(stdout, buffer, buffer_len);
        const DetectDatarepData *sd = (const DetectDatarepData *) smd->ctx;
        int r = DetectDatarepBufferMatch(det_ctx, sd, buffer, buffer_len); //TODO buffer offset?
        if (r == 1) {
            goto match;
        }
        goto no_match_discontinue;

    } else if (smd->type == DETECT_AL_URILEN) {
        SCLogDebug("inspecting uri len");

        int r;
        const DetectUrilenData *urilend = (const DetectUrilenData *)smd->ctx;
        if (buffer_len > UINT16_MAX) {
            r = DetectU16Match(UINT16_MAX, &urilend->du16);
        } else {
            r = DetectU16Match((uint16_t)buffer_len, &urilend->du16);
        }

        if (r == 1) {
            goto match;
        }
        goto no_match_discontinue;
    } else if (smd->type == DETECT_LUA) {
        SCLogDebug("lua starting");

        if (DetectLuaMatchBuffer(det_ctx, s, smd, buffer, buffer_len,
                    det_ctx->buffer_offset, f) != 1)
        {
            SCLogDebug("lua no_match");
            goto no_match;
        }
        SCLogDebug("lua match");
        goto match;
    } else if (smd->type == DETECT_BASE64_DECODE) {
        if (DetectBase64DecodeDoMatch(det_ctx, s, smd, buffer, buffer_len)) {
            if (s->sm_arrays[DETECT_SM_LIST_BASE64_DATA] != NULL) {
                if (det_ctx->base64_decoded_len) {
                    KEYWORD_PROFILING_END(det_ctx, smd->type, 1);
                    int r = DetectEngineContentInspectionInternal(det_ctx, ctx, s,
                            s->sm_arrays[DETECT_SM_LIST_BASE64_DATA], NULL, f,
                            det_ctx->base64_decoded, det_ctx->base64_decoded_len, 0,
                            DETECT_CI_FLAGS_SINGLE, DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE);
                    if (r == 1) {
                        /* Base64 is a terminal list. */
                        goto final_match;
                    }
                }
            }
        }
    } else if (smd->type == DETECT_ASN1) {
        if (!DetectAsn1Match(smd, buffer, buffer_len, det_ctx->buffer_offset)) {
            SCLogDebug("asn1 no_match");
            goto no_match;
        }
        SCLogDebug("asn1 match");
        goto match;
    } else {
        SCLogDebug("sm->type %u", smd->type);
#ifdef DEBUG
        BUG_ON(1);
#endif
    }

no_match:
    KEYWORD_PROFILING_END(det_ctx, smd->type, 0);
    SCReturnInt(0);

no_match_discontinue:
    KEYWORD_PROFILING_END(det_ctx, smd->type, 0);
    SCReturnInt(-1);

match:
    /* this sigmatch matched, inspect the next one. If it was the last,
     * the buffer portion of the signature matched. */
    if (!smd->is_last) {
        KEYWORD_PROFILING_END(det_ctx, smd->type, 1);
        int r = DetectEngineContentInspectionInternal(det_ctx, ctx, s, smd + 1, p, f, buffer,
                buffer_len, stream_start_offset, flags, inspection_mode);
        SCReturnInt(r);
    }
final_match:
    KEYWORD_PROFILING_END(det_ctx, smd->type, 1);
    SCReturnInt(1);
}

/** \brief wrapper around DetectEngineContentInspectionInternal to return true/false only
 *
 *  \param smd sigmatches to evaluate
 */
bool DetectEngineContentInspection(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd, Packet *p, Flow *f, const uint8_t *buffer,
        const uint32_t buffer_len, const uint32_t stream_start_offset, const uint8_t flags,
        const enum DetectContentInspectionType inspection_mode)
{
    struct DetectEngineContentInspectionCtx ctx = { .recursion.count = 0,
        .recursion.limit = de_ctx->inspection_recursion_limit };
    det_ctx->buffer_offset = 0;

    int r = DetectEngineContentInspectionInternal(det_ctx, &ctx, s, smd, p, f, buffer, buffer_len,
            stream_start_offset, flags, inspection_mode);
#ifdef UNITTESTS
    ut_inspection_recursion_counter = ctx.recursion.count;
#endif
    if (r == 1)
        return true;
    else
        return false;
}

/** \brief wrapper around DetectEngineContentInspectionInternal to return true/false only
 *
 *  \param smd sigmatches to evaluate
 */
bool DetectEngineContentInspectionBuffer(DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd, Packet *p, Flow *f, const InspectionBuffer *b,
        const enum DetectContentInspectionType inspection_mode)
{
    struct DetectEngineContentInspectionCtx ctx = { .recursion.count = 0,
        .recursion.limit = de_ctx->inspection_recursion_limit };

    det_ctx->buffer_offset = 0;

    int r = DetectEngineContentInspectionInternal(det_ctx, &ctx, s, smd, p, f, b->inspect,
            b->inspect_len, b->inspect_offset, b->flags, inspection_mode);
#ifdef UNITTESTS
    ut_inspection_recursion_counter = ctx.recursion.count;
#endif
    if (r == 1)
        return true;
    else
        return false;
}

bool DetectContentInspectionMatchOnAbsentBuffer(const SigMatchData *smd)
{
    // we will match on NULL buffers there is one absent
    bool absent_data = false;
    while (1) {
        if (smd->type == DETECT_ABSENT) {
            absent_data = true;
            break;
        }
        if (smd->is_last) {
            break;
        }
        // smd does not get reused after this loop
        smd++;
    }
    return absent_data;
}

#ifdef UNITTESTS
#include "tests/detect-engine-content-inspection.c"
#endif

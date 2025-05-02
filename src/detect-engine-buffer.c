/* Copyright (C) 2025 Open Information Security Foundation
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
 */

#include "suricata-common.h"
#include "detect-engine.h"
#include "detect-parse.h"
#include "detect-engine-buffer.h"

int SCDetectBufferSetActiveList(DetectEngineCtx *de_ctx, Signature *s, const int list)
{
    BUG_ON(s->init_data == NULL);

    if (s->init_data->list == DETECT_SM_LIST_BASE64_DATA) {
        SCLogError("Rule buffer cannot be reset after base64_data.");
        return -1;
    }

    if (s->init_data->list && s->init_data->transforms.cnt) {
        SCLogError("no matches following transform(s)");
        return -1;
    }
    s->init_data->list = list;
    s->init_data->list_set = true;

    // check if last has matches -> if no, error
    if (s->init_data->curbuf && s->init_data->curbuf->head == NULL) {
        SCLogError("previous sticky buffer has no matches");
        return -1;
    }

    for (uint32_t x = 0; x < s->init_data->buffers_size; x++) {
        SignatureInitDataBuffer *b = &s->init_data->buffers[x];
        for (SigMatch *sm = b->head; sm != NULL; sm = sm->next) {
            SCLogDebug(
                    "buf:%p: id:%u: '%s' pos %u", b, b->id, sigmatch_table[sm->type].name, sm->idx);
        }
        if ((uint32_t)list == b->id) {
            SCLogDebug("found buffer %p for list %d", b, list);
            if (s->init_data->buffers[x].sm_init) {
                s->init_data->buffers[x].sm_init = false;
                SCLogDebug("sm_init was true for %p list %d", b, list);
                s->init_data->curbuf = b;
                return 0;

            } else if (DetectEngineBufferTypeSupportsMultiInstanceGetById(de_ctx, list)) {
                // fall through
            } else if (!b->only_ts && (s->init_data->init_flags & SIG_FLAG_INIT_FORCE_TOSERVER)) {
                // fall through
            } else if (!b->only_tc && (s->init_data->init_flags & SIG_FLAG_INIT_FORCE_TOCLIENT)) {
                // fall through
            } else {
                // we create a new buffer for the same id but forced different direction
                SCLogWarning("duplicate instance for %s in '%s'",
                        DetectEngineBufferTypeGetNameById(de_ctx, list), s->sig_str);
                s->init_data->curbuf = b;
                return 0;
            }
        }
    }

    if (list < DETECT_SM_LIST_MAX)
        return 0;

    if (SignatureInitDataBufferCheckExpand(s) < 0) {
        SCLogError("failed to expand rule buffer array");
        return -1;
    }

    /* initialize new buffer */
    s->init_data->curbuf = &s->init_data->buffers[s->init_data->buffer_index++];
    s->init_data->curbuf->id = list;
    s->init_data->curbuf->head = NULL;
    s->init_data->curbuf->tail = NULL;
    s->init_data->curbuf->multi_capable =
            DetectEngineBufferTypeSupportsMultiInstanceGetById(de_ctx, list);
    if (s->init_data->init_flags & SIG_FLAG_INIT_FORCE_TOCLIENT) {
        s->init_data->curbuf->only_tc = true;
    }
    if (s->init_data->init_flags & SIG_FLAG_INIT_FORCE_TOSERVER) {
        s->init_data->curbuf->only_ts = true;
    }

    SCLogDebug("new: idx %u list %d set up curbuf %p", s->init_data->buffer_index - 1, list,
            s->init_data->curbuf);

    return 0;
}

int DetectBufferGetActiveList(DetectEngineCtx *de_ctx, Signature *s)
{
    BUG_ON(s->init_data == NULL);

    if (s->init_data->list && s->init_data->transforms.cnt) {
        if (s->init_data->list == DETECT_SM_LIST_NOTSET ||
                s->init_data->list < DETECT_SM_LIST_DYNAMIC_START) {
            SCLogError("previous transforms not consumed "
                       "(list: %u, transform_cnt %u)",
                    s->init_data->list, s->init_data->transforms.cnt);
            SCReturnInt(-1);
        }

        SCLogDebug("buffer %d has transform(s) registered: %d", s->init_data->list,
                s->init_data->transforms.cnt);
        int new_list = DetectEngineBufferTypeGetByIdTransforms(de_ctx, s->init_data->list,
                s->init_data->transforms.transforms, s->init_data->transforms.cnt);
        if (new_list == -1) {
            SCReturnInt(-1);
        }
        int base_list = s->init_data->list;
        SCLogDebug("new_list %d", new_list);
        s->init_data->list = new_list;
        s->init_data->list_set = false;
        // reset transforms now that we've set up the list
        s->init_data->transforms.cnt = 0;

        if (s->init_data->curbuf && s->init_data->curbuf->head != NULL) {
            if (SignatureInitDataBufferCheckExpand(s) < 0) {
                SCLogError("failed to expand rule buffer array");
                return -1;
            }
            s->init_data->curbuf = &s->init_data->buffers[s->init_data->buffer_index++];
            s->init_data->curbuf->multi_capable =
                    DetectEngineBufferTypeSupportsMultiInstanceGetById(de_ctx, base_list);
        }
        if (s->init_data->curbuf == NULL) {
            SCLogError("failed to setup buffer");
            DEBUG_VALIDATE_BUG_ON(1);
            SCReturnInt(-1);
        }
        s->init_data->curbuf->id = new_list;
        SCLogDebug("new list after applying transforms: %u", new_list);
    }

    SCReturnInt(0);
}

SigMatch *DetectBufferGetFirstSigMatch(const Signature *s, const uint32_t buf_id)
{
    for (uint32_t i = 0; i < s->init_data->buffer_index; i++) {
        if (buf_id == s->init_data->buffers[i].id) {
            return s->init_data->buffers[i].head;
        }
    }
    return NULL;
}

SigMatch *DetectBufferGetLastSigMatch(const Signature *s, const uint32_t buf_id)
{
    SigMatch *last = NULL;
    for (uint32_t i = 0; i < s->init_data->buffer_index; i++) {
        if (buf_id == s->init_data->buffers[i].id) {
            last = s->init_data->buffers[i].tail;
        }
    }
    return last;
}

int SCDetectSignatureAddTransform(Signature *s, int transform, void *options)
{
    /* we only support buffers */
    if (s->init_data->list == 0) {
        SCReturnInt(-1);
    }
    if (!s->init_data->list_set) {
        SCLogError("transforms must directly follow stickybuffers");
        SCReturnInt(-1);
    }
    if (s->init_data->transforms.cnt >= DETECT_TRANSFORMS_MAX) {
        SCReturnInt(-1);
    }

    s->init_data->transforms.transforms[s->init_data->transforms.cnt].transform = transform;
    s->init_data->transforms.transforms[s->init_data->transforms.cnt].options = options;

    s->init_data->transforms.cnt++;
    SCLogDebug("Added transform #%d [%s]", s->init_data->transforms.cnt, s->sig_str);

    SCReturnInt(0);
}

/* Copyright (C) 2015-2018 Open Information Security Foundation
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

/*
 * TODO: Update the \author in this file and detect-template-buffer.h.
 * TODO: Update description in the \file section below.
 * TODO: Remove SCLogNotice statements or convert to debug.
 */

/**
 * \file
 *
 * \author FirstName LastName <yourname@domain>
 *
 * Set up of the "template_buffer" keyword to allow content
 * inspections on the decoded template application layer buffers.
 */

#include "suricata-common.h"
#ifdef UNITTESTS
#include "detect.h"
#include "conf.h"
#endif
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "app-layer-template.h"
#include "detect-template-buffer.h"

static int DetectTemplateBufferSetup(DetectEngineCtx *, Signature *, const char *);
static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *_f, const uint8_t flow_flags,
        void *txv, const int list_id);
#ifdef UNITTESTS
static void DetectTemplateBufferRegisterTests(void);
#endif
static int g_template_buffer_id = 0;

void DetectTemplateBufferRegister(void)
{
    /* TEMPLATE_START_REMOVE */
    /* Prevent registration of this buffer unless explicitly enabled or when
     * running unittests. This will be removed during code generation from this
     * template. */
    if (!RunmodeIsUnittests()) {
        if (ConfGetNode("app-layer.protocols.template") == NULL) {
            return;
        }
    }
    /* TEMPLATE_END_REMOVE */
    sigmatch_table[DETECT_AL_TEMPLATE_BUFFER].name = "template_buffer";
    sigmatch_table[DETECT_AL_TEMPLATE_BUFFER].desc =
            "Template content modifier to match on the template buffers";
    sigmatch_table[DETECT_AL_TEMPLATE_BUFFER].Setup = DetectTemplateBufferSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_AL_TEMPLATE_BUFFER].RegisterTests =
        DetectTemplateBufferRegisterTests;
#endif

    sigmatch_table[DETECT_AL_TEMPLATE_BUFFER].flags |= SIGMATCH_NOOPT;

    /* register inspect engines - these are called per signature */
    DetectAppLayerInspectEngineRegister2("template_buffer",
            ALPROTO_TEMPLATE, SIG_FLAG_TOSERVER, 0,
            DetectEngineInspectBufferGeneric, GetData);
    DetectAppLayerInspectEngineRegister2("template_buffer",
            ALPROTO_TEMPLATE, SIG_FLAG_TOCLIENT, 0,
            DetectEngineInspectBufferGeneric, GetData);

    /* register mpm engines - these are called in the prefilter stage */
    DetectAppLayerMpmRegister2("template_buffer", SIG_FLAG_TOSERVER, 0,
            PrefilterGenericMpmRegister, GetData,
            ALPROTO_TEMPLATE, 0);
    DetectAppLayerMpmRegister2("template_buffer", SIG_FLAG_TOCLIENT, 0,
            PrefilterGenericMpmRegister, GetData,
            ALPROTO_TEMPLATE, 0);


    g_template_buffer_id = DetectBufferTypeGetByName("template_buffer");

    /* NOTE: You may want to change this to SCLogNotice during development. */
    SCLogDebug("Template application layer detect registered.");
}

static int DetectTemplateBufferSetup(DetectEngineCtx *de_ctx, Signature *s,
    const char *str)
{
    /* store list id. Content, pcre, etc will be added to the list at this
     * id. */
    s->init_data->list = g_template_buffer_id;

    /* set the app proto for this signature. This means it will only be
     * evaluated against flows that are ALPROTO_TEMPLATE */
    if (DetectSignatureSetAppProto(s, ALPROTO_TEMPLATE) != 0)
        return -1;

    return 0;
}

/** \internal
 *  \brief get the data to inspect from the transaction.
 *  This function gets the data, sets up the InspectionBuffer object
 *  and applies transformations (if any).
 *
 *  \retval buffer or NULL in case of error
 */
static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms,
        Flow *_f, const uint8_t flow_flags,
        void *txv, const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        const TemplateTransaction  *tx = (TemplateTransaction *)txv;
        const uint8_t *data = NULL;
        uint32_t data_len = 0;

        if (flow_flags & STREAM_TOSERVER) {
            data = tx->request_buffer;
            data_len = tx->request_buffer_len;
        } else if (flow_flags & STREAM_TOCLIENT) {
            data = tx->response_buffer;
            data_len = tx->response_buffer_len;
        } else {
            return NULL; /* no buffer */
        }

        InspectionBufferSetup(det_ctx, list_id, buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

#ifdef UNITTESTS
#include "tests/detect-template-buffer.c"
#endif

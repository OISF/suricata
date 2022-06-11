/* Copyright (C) 2022 Open Information Security Foundation
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
 * TODO: Remove SCLogNotice statements or convert to debug.
 */

/**
 * \file
 *
 * \author Eric Leblond <el@stamus-networks.com>
 *
 * Offer source or destination IP as a sticky buffer.
 */

#include "suricata-common.h"

#include "decode.h"
#include "conf.h"
#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"
#include "detect-ipaddr.h"

#define KEYWORD_NAME_SRC "ip.src"

static int DetectIPAddrBufferSetup(DetectEngineCtx *, Signature *, const char *);
static InspectionBuffer *GetData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Packet *p, const int list_id);

#ifdef UNITTESTS
static void DetectIPAddrRegisterTests(void);
#endif
static int g_src_ipaddr_buffer_id = 0;

void DetectIPAddrBufferRegister(void)
{
    sigmatch_table[DETECT_IPADDR_SRC].name = KEYWORD_NAME_SRC;
    sigmatch_table[DETECT_IPADDR_SRC].desc = "Sticky buffer for src_ip";
    sigmatch_table[DETECT_IPADDR_SRC].Setup = DetectIPAddrBufferSetup;
#ifdef UNITTESTS
    sigmatch_table[DETECT_IPADDR_SRC].RegisterTests = DetectIPAddrRegisterTests;
#endif

    sigmatch_table[DETECT_IPADDR_SRC].flags |= SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER;

    g_src_ipaddr_buffer_id = DetectBufferTypeRegister(KEYWORD_NAME_SRC);
    BUG_ON(g_src_ipaddr_buffer_id < 0);

    DetectBufferTypeSupportsPacket(KEYWORD_NAME_SRC);

    DetectPktMpmRegister(KEYWORD_NAME_SRC, 2, PrefilterGenericMpmPktRegister, GetData);

    DetectPktInspectEngineRegister(KEYWORD_NAME_SRC, GetData, DetectEngineInspectPktBufferGeneric);

    /* NOTE: You may want to change this to SCLogNotice during development. */
    SCLogDebug("IPAddr detect registered.");
}

static int DetectIPAddrBufferSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    /* store list id. Content, pcre, etc will be added to the list at this
     * id. */
    s->init_data->list = g_src_ipaddr_buffer_id;

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
        const DetectEngineTransforms *transforms, Packet *p, const int list_id)
{
    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);
    if (buffer->inspect == NULL) {
        InspectionBufferSetup(det_ctx, list_id, buffer, p->src.address.address_un_data8, 16);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

#ifdef UNITTESTS
#include "tests/detect-ipaddr.c"
#endif

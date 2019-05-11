/* Copyright (C) 2007-2016 Open Information Security Foundation
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
 * \ingroup sshlayer
 *
 * @{
 */


/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
 *
 * Implements support ssh_proto sticky buffer
 */

#include "suricata-common.h"
#include "threads.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"
#include "detect-engine-prefilter.h"
#include "detect-engine-content-inspection.h"

#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-ssh.h"
#include "detect-ssh-proto.h"

#define KEYWORD_NAME "ssh.proto"
#define KEYWORD_NAME_LEGACY "ssh_proto"
#define KEYWORD_DOC "ssh-keywords.html#ssh-proto"
#define BUFFER_NAME "ssh_protocol"
#define BUFFER_DESC "ssh protocol field"
static int g_buffer_id = 0;

static InspectionBuffer *GetSshData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f,
        const uint8_t flow_flags, void *txv, const int list_id)
{
    SCEnter();

    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);

    if (buffer->inspect == NULL) {
        uint8_t *protocol = NULL;
        SshState *ssh_state = (SshState *) txv;

        if (flow_flags & STREAM_TOSERVER)
            protocol = ssh_state->cli_hdr.proto_version;
        else if (flow_flags & STREAM_TOCLIENT)
            protocol = ssh_state->srv_hdr.proto_version;

        if (protocol == NULL) {
            SCLogDebug("SSL protocol not set");
            return NULL;
        }

        uint32_t data_len = strlen((char *)protocol);
        uint8_t *data = protocol;
        if (data == NULL || data_len == 0) {
            SCLogDebug("SSL protocol not present");
            return NULL;
        }

        InspectionBufferSetup(buffer, data, data_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

static int DetectSshProtocolSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (DetectBufferSetActiveList(s, g_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_SSH) < 0)
        return -1;

    return 0;
}

void DetectSshProtocolRegister(void)
{
    sigmatch_table[DETECT_AL_SSH_PROTOCOL].name = KEYWORD_NAME;
    sigmatch_table[DETECT_AL_SSH_PROTOCOL].alias = KEYWORD_NAME_LEGACY;
    sigmatch_table[DETECT_AL_SSH_PROTOCOL].desc = BUFFER_NAME " sticky buffer";
    sigmatch_table[DETECT_AL_SSH_PROTOCOL].url = DOC_URL DOC_VERSION "/rules/" KEYWORD_DOC;
    sigmatch_table[DETECT_AL_SSH_PROTOCOL].Setup = DetectSshProtocolSetup;
    sigmatch_table[DETECT_AL_SSH_PROTOCOL].flags |= SIGMATCH_INFO_STICKY_BUFFER | SIGMATCH_NOOPT;


    DetectAppLayerMpmRegister2(BUFFER_NAME, SIG_FLAG_TOSERVER, 2,
            PrefilterGenericMpmRegister, GetSshData,
			ALPROTO_SSH, SSH_STATE_BANNER_DONE),
    DetectAppLayerMpmRegister2(BUFFER_NAME, SIG_FLAG_TOCLIENT, 2,
            PrefilterGenericMpmRegister, GetSshData,
			ALPROTO_SSH, SSH_STATE_BANNER_DONE),

    DetectAppLayerInspectEngineRegister2(BUFFER_NAME,
            ALPROTO_SSH, SIG_FLAG_TOSERVER, SSH_STATE_BANNER_DONE,
            DetectEngineInspectBufferGeneric, GetSshData);
    DetectAppLayerInspectEngineRegister2(BUFFER_NAME,
            ALPROTO_SSH, SIG_FLAG_TOCLIENT, SSH_STATE_BANNER_DONE,
            DetectEngineInspectBufferGeneric, GetSshData);

    DetectBufferTypeSetDescriptionByName(BUFFER_NAME, BUFFER_DESC);

    g_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);
}

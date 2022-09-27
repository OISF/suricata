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

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"

#include "detect-ssh-proto.h"
#include "rust.h"

#define KEYWORD_NAME "ssh.proto"
#define KEYWORD_NAME_LEGACY "ssh_proto"
#define KEYWORD_DOC "ssh-keywords.html#ssh-proto"
#define BUFFER_NAME "ssh.proto"
#define BUFFER_DESC "ssh protocol version field"
static int g_buffer_id = 0;

static InspectionBuffer *GetSshData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f,
        const uint8_t flow_flags, void *txv, const int list_id)
{
    SCEnter();

    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);

    if (buffer->inspect == NULL) {
        const uint8_t *protocol = NULL;
        uint32_t b_len = 0;

        if (rs_ssh_tx_get_protocol(txv, &protocol, &b_len, flow_flags) != 1)
            return NULL;
        if (protocol == NULL || b_len == 0) {
            SCLogDebug("SSH protocol not set");
            return NULL;
        }

        InspectionBufferSetup(det_ctx, list_id, buffer, protocol, b_len);
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
    sigmatch_table[DETECT_AL_SSH_PROTOCOL].url = "/rules/" KEYWORD_DOC;
    sigmatch_table[DETECT_AL_SSH_PROTOCOL].Setup = DetectSshProtocolSetup;
    sigmatch_table[DETECT_AL_SSH_PROTOCOL].flags |= SIGMATCH_INFO_STICKY_BUFFER | SIGMATCH_NOOPT;


    DetectAppLayerMpmRegister2(BUFFER_NAME, SIG_FLAG_TOSERVER, 2,
            PrefilterGenericMpmRegister, GetSshData,
			ALPROTO_SSH, SshStateBannerDone),
    DetectAppLayerMpmRegister2(BUFFER_NAME, SIG_FLAG_TOCLIENT, 2,
            PrefilterGenericMpmRegister, GetSshData,
			ALPROTO_SSH, SshStateBannerDone),

    DetectAppLayerInspectEngineRegister2(BUFFER_NAME,
            ALPROTO_SSH, SIG_FLAG_TOSERVER, SshStateBannerDone,
            DetectEngineInspectBufferGeneric, GetSshData);
    DetectAppLayerInspectEngineRegister2(BUFFER_NAME,
            ALPROTO_SSH, SIG_FLAG_TOCLIENT, SshStateBannerDone,
            DetectEngineInspectBufferGeneric, GetSshData);

    DetectBufferTypeSetDescriptionByName(BUFFER_NAME, BUFFER_DESC);

    g_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);
}

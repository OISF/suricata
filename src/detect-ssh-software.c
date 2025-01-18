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
 * Implements support ssh_software sticky buffer
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
#include "detect-ssh-software.h"
#include "rust.h"

#define KEYWORD_NAME "ssh.software"
#define KEYWORD_NAME_LEGACY "ssh_software"
#define KEYWORD_DOC "ssh-keywords.html#ssh-software"
#define BUFFER_NAME "ssh_software"
#define BUFFER_DESC "ssh software field"
static int g_buffer_id = 0;

static InspectionBuffer *GetSshData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f,
        const uint8_t flow_flags, void *txv, const int list_id)
{
    SCEnter();

    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);

    if (buffer->inspect == NULL) {
        const uint8_t *software = NULL;
        uint32_t b_len = 0;

        if (rs_ssh_tx_get_software(txv, &software, &b_len, flow_flags) != 1)
            return NULL;
        if (software == NULL || b_len == 0) {
            SCLogDebug("SSH software version not set");
            return NULL;
        }

        InspectionBufferSetup(det_ctx, list_id, buffer, software, b_len);
        InspectionBufferApplyTransforms(det_ctx, buffer, transforms);
    }

    return buffer;
}

static int DetectSshSoftwareSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (DetectBufferSetActiveList(de_ctx, s, g_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_SSH) < 0)
        return -1;

    return 0;
}


void DetectSshSoftwareRegister(void)
{
    sigmatch_table[DETECT_AL_SSH_SOFTWARE].name = KEYWORD_NAME;
    sigmatch_table[DETECT_AL_SSH_SOFTWARE].alias = KEYWORD_NAME_LEGACY;
    sigmatch_table[DETECT_AL_SSH_SOFTWARE].desc = BUFFER_NAME " sticky buffer";
    sigmatch_table[DETECT_AL_SSH_SOFTWARE].url = "/rules/" KEYWORD_DOC;
    sigmatch_table[DETECT_AL_SSH_SOFTWARE].Setup = DetectSshSoftwareSetup;
    sigmatch_table[DETECT_AL_SSH_SOFTWARE].flags |= SIGMATCH_INFO_STICKY_BUFFER | SIGMATCH_NOOPT;

    DetectAppLayerMpmRegister(BUFFER_NAME, SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetSshData, ALPROTO_SSH, SshStateBannerDone),
            DetectAppLayerMpmRegister(BUFFER_NAME, SIG_FLAG_TOCLIENT, 2,
                    PrefilterGenericMpmRegister, GetSshData, ALPROTO_SSH, SshStateBannerDone),

            DetectAppLayerInspectEngineRegister(BUFFER_NAME, ALPROTO_SSH, SIG_FLAG_TOSERVER,
                    SshStateBannerDone, DetectEngineInspectBufferGeneric, GetSshData);
    DetectAppLayerInspectEngineRegister(BUFFER_NAME, ALPROTO_SSH, SIG_FLAG_TOCLIENT,
            SshStateBannerDone, DetectEngineInspectBufferGeneric, GetSshData);

    DetectBufferTypeSetDescriptionByName(BUFFER_NAME, BUFFER_DESC);

    g_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);
}

/* Copyright (C) 2007-2020 Open Information Security Foundation
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
 * \author Vadym Malakhatko <v.malakhatko@sirinsoftware.com>
 */

#include "suricata-common.h"
#include "threads.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"
#include "detect-content.h"

#include "detect-engine.h"
#include "detect-engine-buffer.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"
#include "detect-engine-prefilter.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "util-debug.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"
#include "stream-tcp.h"
#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-ssh.h"
#include "detect-ssh-hassh.h"
#include "rust.h"


#define KEYWORD_NAME "ssh.hassh"
#define KEYWORD_ALIAS "ssh-hassh"
#define KEYWORD_DOC "ssh-keywords.html#hassh"
#define BUFFER_NAME "ssh.hassh"
#define BUFFER_DESC "Ssh Client Fingerprinting For Ssh Clients "
static int g_ssh_hassh_buffer_id = 0;


static InspectionBuffer *GetSshData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f,
        const uint8_t flow_flags, void *txv, const int list_id)
{

    SCEnter();

    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);

    if (buffer->inspect == NULL) {
        const uint8_t *hassh = NULL;
        uint32_t b_len = 0;

        if (SCSshTxGetHassh(txv, &hassh, &b_len, flow_flags) != 1)
            return NULL;
        if (hassh == NULL || b_len == 0) {
            SCLogDebug("SSH hassh not set");
            return NULL;
        }

        InspectionBufferSetupAndApplyTransforms(det_ctx, list_id, buffer, hassh, b_len, transforms);
    }

    return buffer;
}

/**
 * \brief this function setup the hassh modifier keyword used in the rule
 *
 * \param de_ctx Pointer to the Detection Engine Context
 * \param s      Pointer to the Signature to which the current keyword belongs
 * \param str    Should hold an empty string always
 *
 * \retval 0  On success
 * \retval -1 On failure
 * \retval -2 on failure that should be silent after the first
 */
static int DetectSshHasshSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (SCDetectBufferSetActiveList(de_ctx, s, g_ssh_hassh_buffer_id) < 0)
        return -1;

    if (SCDetectSignatureSetAppProto(s, ALPROTO_SSH) < 0)
        return -1;
        
    /* try to enable Hassh */
    SCSshEnableHassh();

    /* Check if Hassh is disabled */
    if (!RunmodeIsUnittests() && !SCSshHasshIsEnabled()) {
        if (!SigMatchSilentErrorEnabled(de_ctx, DETECT_SSH_HASSH)) {
            SCLogError("hassh support is not enabled");
        }
        return -2;
    }

    return 0;

}

static void DetectSshHasshHashSetupCallback(const DetectEngineCtx *de_ctx,
                                          Signature *s)
{
    for (uint32_t x = 0; x < s->init_data->buffer_index; x++) {
        if (s->init_data->buffers[x].id != (uint32_t)g_ssh_hassh_buffer_id)
            continue;
        SigMatch *sm = s->init_data->buffers[x].head;
        for (; sm != NULL; sm = sm->next) {
            if (sm->type != DETECT_CONTENT)
                continue;

            DetectContentData *cd = (DetectContentData *)sm->ctx;

            uint32_t u;
            for (u = 0; u < cd->content_len; u++) {
                if (isupper(cd->content[u])) {
                    cd->content[u] = u8_tolower(cd->content[u]);
                }
            }

            SpmDestroyCtx(cd->spm_ctx);
            cd->spm_ctx =
                    SpmInitCtx(cd->content, cd->content_len, 1, de_ctx->spm_global_thread_ctx);
        }
    }
}

/**
 * \brief Registration function for hassh keyword.
 */
void DetectSshHasshRegister(void) 
{
    sigmatch_table[DETECT_SSH_HASSH].name = KEYWORD_NAME;
    sigmatch_table[DETECT_SSH_HASSH].alias = KEYWORD_ALIAS;
    sigmatch_table[DETECT_SSH_HASSH].desc = BUFFER_NAME " sticky buffer";
    sigmatch_table[DETECT_SSH_HASSH].url = "/rules/" KEYWORD_DOC;
    sigmatch_table[DETECT_SSH_HASSH].Setup = DetectSshHasshSetup;
    sigmatch_table[DETECT_SSH_HASSH].flags |= SIGMATCH_INFO_STICKY_BUFFER | SIGMATCH_NOOPT;

    DetectAppLayerMpmRegister(BUFFER_NAME, SIG_FLAG_TOSERVER, 2, PrefilterGenericMpmRegister,
            GetSshData, ALPROTO_SSH, SshStateBannerDone),
            DetectAppLayerInspectEngineRegister(BUFFER_NAME, ALPROTO_SSH, SIG_FLAG_TOSERVER,
                    SshStateBannerDone, DetectEngineInspectBufferGeneric, GetSshData);
    DetectBufferTypeSetDescriptionByName(BUFFER_NAME, BUFFER_DESC);

    g_ssh_hassh_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);

    DetectBufferTypeRegisterSetupCallback(BUFFER_NAME, DetectSshHasshHashSetupCallback);
    DetectBufferTypeRegisterValidateCallback(BUFFER_NAME, DetectMd5ValidateCallback);
}


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

#include "detect-parse.h"
#include "detect-content.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-prefilter.h"

#include "detect-ssh-hassh-server.h"
#include "rust.h"


#define KEYWORD_NAME "ssh.hassh.server"
#define KEYWORD_ALIAS "ssh-hassh-server"
#define KEYWORD_DOC "ssh-keywords.html#ssh.hassh.server"
#define BUFFER_NAME "ssh.hassh.server"
#define BUFFER_DESC "Ssh Client Fingerprinting For Ssh Servers"
static int g_ssh_hassh_buffer_id = 0;


static InspectionBuffer *GetSshData(DetectEngineThreadCtx *det_ctx,
        const DetectEngineTransforms *transforms, Flow *_f,
        const uint8_t flow_flags, void *txv, const int list_id)
{
    
    SCEnter();

    InspectionBuffer *buffer = InspectionBufferGet(det_ctx, list_id);

    if (buffer->inspect == NULL) {
        const uint8_t *hasshServer = NULL;
        uint32_t b_len = 0;

        if (rs_ssh_tx_get_hassh(txv, &hasshServer, &b_len, flow_flags) != 1)
            return NULL;
        if (hasshServer == NULL || b_len == 0) {
            SCLogDebug("SSH hassh not set");
            return NULL;
        }

        InspectionBufferSetup(det_ctx, list_id, buffer, hasshServer, b_len);
        InspectionBufferApplyTransforms(buffer, transforms);
    }

    return buffer;
}

/**
 * \brief this function setup the ssh.hassh.server modifier keyword used in the rule
 *
 * \param de_ctx Pointer to the Detection Engine Context
 * \param s      Pointer to the Signature to which the current keyword belongs
 * \param str    Should hold an empty string always
 *
 * \retval 0  On success
 * \retval -1 On failure
 * \retval -2 on failure that should be silent after the first
 */
static int DetectSshHasshServerSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    if (DetectBufferSetActiveList(s, g_ssh_hassh_buffer_id) < 0)
        return -1;

    if (DetectSignatureSetAppProto(s, ALPROTO_SSH) < 0)
        return -1;
            
    /* try to enable Hassh */
    rs_ssh_enable_hassh();

    /* Check if Hassh is disabled */
    if (!RunmodeIsUnittests() && !rs_ssh_hassh_is_enabled()) {
        if (!SigMatchSilentErrorEnabled(de_ctx, DETECT_AL_SSH_HASSH_SERVER)) {
            SCLogError(SC_WARN_HASSH_DISABLED, "hassh support is not enabled");
        }
        return -2;
    }

    return 0;

}

static bool DetectSshHasshServerHashValidateCallback(const Signature *s, const char **sigerror)
{
    const SigMatch *sm = s->init_data->smlists[g_ssh_hassh_buffer_id];
    for ( ; sm != NULL; sm = sm->next)
    {
        if (sm->type != DETECT_CONTENT)
            continue;

        const DetectContentData *cd = (DetectContentData *)sm->ctx;

        if (cd->flags & DETECT_CONTENT_NOCASE) {
            *sigerror = "ssh.hassh.server should not be used together with "
                        "nocase, since the rule is automatically "
                        "lowercased anyway which makes nocase redundant.";
            SCLogWarning(SC_WARN_POOR_RULE, "rule %u: %s", s->id, *sigerror);
        }

        if (cd->content_len != 32)
        {
            *sigerror = "Invalid length of the specified ssh.hassh.server (should "
                        "be 32 characters long). This rule will therefore "
                        "never match.";
            SCLogWarning(SC_WARN_POOR_RULE,  "rule %u: %s", s->id, *sigerror);
            return false;
        }
        for (size_t i = 0; i < cd->content_len; ++i)
        {
            if(!isxdigit(cd->content[i])) 
            {
                *sigerror = "Invalid ssh.hassh.server string (should be string of hexademical characters)."
                            "This rule will therefore never match.";
                SCLogWarning(SC_WARN_POOR_RULE,  "rule %u: %s", s->id, *sigerror);
                return false;
            }
        }
    }

    return true;
}

static void DetectSshHasshServerHashSetupCallback(const DetectEngineCtx *de_ctx,
                                          Signature *s)
{
    SigMatch *sm = s->init_data->smlists[g_ssh_hassh_buffer_id];
    for ( ; sm != NULL; sm = sm->next)
    {
        if (sm->type != DETECT_CONTENT)
            continue;

        DetectContentData *cd = (DetectContentData *)sm->ctx;

        uint32_t u;
        for (u = 0; u < cd->content_len; u++)
        {
            if (isupper(cd->content[u])) {
                cd->content[u] = u8_tolower(cd->content[u]);
            }
        }

        SpmDestroyCtx(cd->spm_ctx);
        cd->spm_ctx = SpmInitCtx(cd->content, cd->content_len, 1,
        		de_ctx->spm_global_thread_ctx);
    }
}

/**
 * \brief Registration function for hasshServer keyword.
 */
void DetectSshHasshServerRegister(void) 
{
    sigmatch_table[DETECT_AL_SSH_HASSH_SERVER].name = KEYWORD_NAME;
    sigmatch_table[DETECT_AL_SSH_HASSH_SERVER].alias = KEYWORD_ALIAS;
    sigmatch_table[DETECT_AL_SSH_HASSH_SERVER].desc = BUFFER_NAME " sticky buffer";
    sigmatch_table[DETECT_AL_SSH_HASSH_SERVER].url = "/rules/" KEYWORD_DOC;
    sigmatch_table[DETECT_AL_SSH_HASSH_SERVER].Setup = DetectSshHasshServerSetup;
    sigmatch_table[DETECT_AL_SSH_HASSH_SERVER].flags |= SIGMATCH_INFO_STICKY_BUFFER | SIGMATCH_NOOPT;

    DetectAppLayerMpmRegister2(BUFFER_NAME, SIG_FLAG_TOCLIENT, 2, 
            PrefilterGenericMpmRegister, GetSshData, 
            ALPROTO_SSH, SshStateBannerDone);
    DetectAppLayerInspectEngineRegister2(BUFFER_NAME, ALPROTO_SSH, 
            SIG_FLAG_TOCLIENT, SshStateBannerDone, 
            DetectEngineInspectBufferGeneric, GetSshData);
    DetectBufferTypeSetDescriptionByName(BUFFER_NAME, BUFFER_DESC);

    g_ssh_hassh_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);

    DetectBufferTypeRegisterSetupCallback(BUFFER_NAME, DetectSshHasshServerHashSetupCallback);
    DetectBufferTypeRegisterValidateCallback(BUFFER_NAME, DetectSshHasshServerHashValidateCallback);
}

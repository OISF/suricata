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

#define KEYWORD_NAME "ssh_proto"
#define KEYWORD_DOC "ssh-keywords#ssh-protocol"
#define BUFFER_NAME "ssh_protocol"
#define BUFFER_DESC "ssh protocol field"
static int g_buffer_id = 0;

/** \brief SSH Protocol Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param pectx inspection context
 */
static void PrefilterTxSshRequestProtocol(DetectEngineThreadCtx *det_ctx,
        const void *pectx,
        Packet *p, Flow *f, void *txv,
        const uint64_t idx, const uint8_t flags)
{
    SCEnter();

    const MpmCtx *mpm_ctx = (MpmCtx *)pectx;
    const SshState *ssh_state = txv;

    if (ssh_state->cli_hdr.proto_version == NULL)
        return;

    uint32_t buffer_len = strlen((char *)ssh_state->cli_hdr.proto_version);
    const uint8_t *buffer = ssh_state->cli_hdr.proto_version;

    if (buffer_len >= mpm_ctx->minlen) {
        (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                &det_ctx->mtcu, &det_ctx->pmq, buffer, buffer_len);
    }
}

static int PrefilterTxSshRequestProtocolRegister(SigGroupHead *sgh, MpmCtx *mpm_ctx)
{
    SCEnter();

    int r = PrefilterAppendTxEngine(sgh, PrefilterTxSshRequestProtocol,
        ALPROTO_SSH, SSH_STATE_BANNER_DONE,
        mpm_ctx, NULL, KEYWORD_NAME " (request)");
    return r;
}

/** \brief SSH Protocol Mpm prefilter callback
 *
 *  \param det_ctx detection engine thread ctx
 *  \param p packet to inspect
 *  \param f flow to inspect
 *  \param txv tx to inspect
 *  \param pectx inspection context
 */
static void PrefilterTxSshResponseProtocol(DetectEngineThreadCtx *det_ctx,
        const void *pectx,
        Packet *p, Flow *f, void *txv,
        const uint64_t idx, const uint8_t flags)
{
    SCEnter();

    const MpmCtx *mpm_ctx = (MpmCtx *)pectx;
    const SshState *ssh_state = txv;

    if (ssh_state->srv_hdr.proto_version == NULL)
        return;

    uint32_t buffer_len = strlen((char *)ssh_state->srv_hdr.proto_version);
    const uint8_t *buffer = ssh_state->srv_hdr.proto_version;

    if (buffer_len >= mpm_ctx->minlen) {
        (void)mpm_table[mpm_ctx->mpm_type].Search(mpm_ctx,
                &det_ctx->mtcu, &det_ctx->pmq, buffer, buffer_len);
    }
}

static int PrefilterTxSshResponseProtocolRegister(SigGroupHead *sgh, MpmCtx *mpm_ctx)
{
    SCEnter();

    int r = PrefilterAppendTxEngine(sgh, PrefilterTxSshResponseProtocol,
        ALPROTO_SSH, SSH_STATE_BANNER_DONE,
        mpm_ctx, NULL, KEYWORD_NAME " (response)");
    return r;
}

static int InspectEngineSshProtocol(ThreadVars *tv,
        DetectEngineCtx *de_ctx, DetectEngineThreadCtx *det_ctx,
        const Signature *s, const SigMatchData *smd,
        Flow *f, uint8_t flags, void *alstate, void *tx, uint64_t tx_id)
{
    uint8_t *protocol = NULL;
    SshState *ssh_state = alstate;

    if (flags & STREAM_TOSERVER)
        protocol = ssh_state->cli_hdr.proto_version;
    else if (flags & STREAM_TOCLIENT)
        protocol = ssh_state->srv_hdr.proto_version;
    if (protocol == NULL)
        goto end;

    uint32_t buffer_len = strlen((char *)protocol);
    uint8_t *buffer = protocol;
    if (buffer == NULL ||buffer_len == 0)
        goto end;

    det_ctx->buffer_offset = 0;
    det_ctx->discontinue_matching = 0;
    det_ctx->inspection_recursion_counter = 0;
    int r = DetectEngineContentInspection(de_ctx, det_ctx, s, smd,
                                          f,
                                          buffer, buffer_len,
                                          0,
                                          DETECT_ENGINE_CONTENT_INSPECTION_MODE_STATE, NULL);
    if (r == 1)
        return DETECT_ENGINE_INSPECT_SIG_MATCH;

 end:
    if (AppLayerParserGetStateProgress(IPPROTO_TCP, ALPROTO_SSH, tx, flags) >= SSH_STATE_BANNER_DONE)
        return DETECT_ENGINE_INSPECT_SIG_CANT_MATCH;
    return DETECT_ENGINE_INSPECT_SIG_NO_MATCH;
}

static int DetectSshProtocolSetup(DetectEngineCtx *de_ctx, Signature *s, const char *arg)
{
    s->init_data->list = g_buffer_id;
    return 0;
}

static void DetectSshProtocolSetupCallback(Signature *s)
{
    SCLogDebug("callback invoked by %u", s->id);
    s->mask |= SIG_MASK_REQUIRE_SSH_STATE;
}

void DetectSshProtocolRegister(void)
{
    sigmatch_table[DETECT_AL_SSH_PROTOCOL].name = KEYWORD_NAME;
    sigmatch_table[DETECT_AL_SSH_PROTOCOL].desc = BUFFER_NAME " sticky buffer";
    sigmatch_table[DETECT_AL_SSH_PROTOCOL].url = DOC_URL DOC_VERSION "/rules/" KEYWORD_DOC;
    sigmatch_table[DETECT_AL_SSH_PROTOCOL].Setup = DetectSshProtocolSetup;
    sigmatch_table[DETECT_AL_SSH_PROTOCOL].flags |= SIGMATCH_NOOPT ;

    DetectAppLayerMpmRegister(BUFFER_NAME, SIG_FLAG_TOSERVER, 2,
            PrefilterTxSshRequestProtocolRegister);
    DetectAppLayerMpmRegister(BUFFER_NAME, SIG_FLAG_TOCLIENT, 2,
            PrefilterTxSshResponseProtocolRegister);

    DetectAppLayerInspectEngineRegister(BUFFER_NAME,
            ALPROTO_SSH, SIG_FLAG_TOSERVER, SSH_STATE_BANNER_DONE,
            InspectEngineSshProtocol);
    DetectAppLayerInspectEngineRegister(BUFFER_NAME,
            ALPROTO_SSH, SIG_FLAG_TOCLIENT, SSH_STATE_BANNER_DONE,
            InspectEngineSshProtocol);

    DetectBufferTypeSetDescriptionByName(BUFFER_NAME,
            BUFFER_DESC);

    DetectBufferTypeRegisterSetupCallback(BUFFER_NAME,
            DetectSshProtocolSetupCallback);

    g_buffer_id = DetectBufferTypeGetByName(BUFFER_NAME);
}

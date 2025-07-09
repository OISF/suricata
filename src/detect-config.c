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
 * \author Victor Julien <victor@inliniac.net>
 *
 * Implements the config keyword
 */

#include "suricata-common.h"
#include "threads.h"
#include "decode.h"

#include "detect.h"
#include "detect-parse.h"

#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-engine-state.h"

#include "flow.h"
#include "flow-var.h"
#include "flow-util.h"

#include "util-debug.h"
#include "util-spm-bm.h"
#include "util-unittest.h"
#include "util-unittest-helper.h"

#include "app-layer.h"
#include "app-layer-parser.h"
#include "app-layer-htp.h"

#include "stream-tcp.h"

#include "detect-config.h"

#include "output.h"

/**
 * \brief Regex for parsing our config keyword options
 */
#define PARSE_REGEX  "^\\s*([A-z_]+)\\s*\\s*([A-z_]+)\\s*(?:,\\s*([A-z_]+)\\s+([A-z_]+))?\\s*(?:,\\s*([A-z_]+)\\s+([A-z_]+))?$"

static DetectParseRegex parse_regex;

static int DetectConfigPostMatch (DetectEngineThreadCtx *det_ctx, Packet *p,
        const Signature *s, const SigMatchCtx *ctx);
static int DetectConfigSetup (DetectEngineCtx *, Signature *, const char *);
static void DetectConfigFree(DetectEngineCtx *, void *);
#ifdef UNITTESTS
static void DetectConfigRegisterTests(void);
#endif

/**
 * \brief Registers the "config" keyword for detection.
 */
void DetectConfigRegister(void)
{
    sigmatch_table[DETECT_CONFIG].name = "config";
    sigmatch_table[DETECT_CONFIG].Match = DetectConfigPostMatch;
    sigmatch_table[DETECT_CONFIG].Setup = DetectConfigSetup;
    sigmatch_table[DETECT_CONFIG].Free  = DetectConfigFree;
    sigmatch_table[DETECT_CONFIG].desc =
            "apply different configuration settings to a flow, packet or other unit";
    sigmatch_table[DETECT_CONFIG].url = "/rules/config.html";
#ifdef UNITTESTS
    sigmatch_table[DETECT_CONFIG].RegisterTests = DetectConfigRegisterTests;
#endif
    sigmatch_table[DETECT_CONFIG].flags = SIGMATCH_SUPPORT_FIREWALL;
    DetectSetupParseRegexes(PARSE_REGEX, &parse_regex);
}

/**
 * \brief Apply configuration settings to a transaction based on the provided DetectConfigData.
 *
 * This function applies specific configurations to a transaction. The configurations are
 * determined by the subsystems and types specified in the DetectConfigData structure.
 *
 * \param f Pointer to the Flow structure that will be configured.
 * \param tx_id Transaction ID within the flow.
 * \param config Pointer to the DetectConfigData structure containing configuration settings.
 */
static void ConfigApplyTx(Flow *f,
        const uint64_t tx_id, const DetectConfigData *config)
{
    if (f->alstate == NULL) {
        return;
    }
    void *tx = AppLayerParserGetTx(f->proto, f->alproto, f->alstate, tx_id);
    if (tx) {
        AppLayerTxData *txd = AppLayerParserGetTxData(f->proto, f->alproto, tx);
        SCLogDebug("tx %p txd %p: log_flags %x", tx, txd, txd->config.log_flags);
        txd->config.log_flags |= BIT_U8(config->type);

        const bool unidir =
                (txd->flags & (APP_LAYER_TX_SKIP_INSPECT_TS | APP_LAYER_TX_SKIP_INSPECT_TC)) != 0;
        if (unidir) {
            SCLogDebug("handle unidir tx");
            AppLayerTxConfig req;
            memset(&req, 0, sizeof(req));
            req.log_flags = BIT_U8(config->type);
            AppLayerParserApplyTxConfig(
                    f->proto, f->alproto, f->alstate, tx, CONFIG_ACTION_SET, req);
        }
    } else {
        SCLogDebug("no tx");
    }
}

/**
 * \brief Apply configuration settings to a packet based on the provided DetectConfigData.
 *
 * This function applies specific configurations to a packet. The configurations are
 * determined by the subsystems and types specified in the DetectConfigData structure.
 *
 * \param p Pointer to the Packet structure that will be configured.
 * \param config Pointer to the DetectConfigData structure containing configuration settings.
 */
static void ConfigApplyPacket(Packet *p, const DetectConfigData *config)
{
    DEBUG_VALIDATE_BUG_ON(config->scope != CONFIG_SCOPE_PACKET);

    switch (config->subsys) {
        case CONFIG_SUBSYS_TRACKING:
            switch (config->type) {
                case CONFIG_TYPE_FLOW:
                    if (p->flags & PKT_WANTS_FLOW) {
                        p->flags &= ~PKT_WANTS_FLOW;
                    }
                    break;
                case CONFIG_TYPE_TX:
                    break;
            }
            break;
        case CONFIG_SUBSYS_LOGGING:
            break;
    }
}

/**
 * \brief Apply configuration settings based on the scope.
 *
 * This function applies post-match configurations with options. It
 * determines which logic to apply based on the scope of the configuration,
 * whether it is packet, transaction (tx), or flow level.
 *
 * \param det_ctx Pointer to the detection engine thread context.
 * \param p Pointer to the current packet being processed.
 * \param config Pointer to the configuration data structure.
 *
 * \retval 0 on success.
 */
static int ConfigApply(DetectEngineThreadCtx *det_ctx,
        Packet *p, const DetectConfigData *config)
{
    bool this_packet = false;
    bool this_tx = false;
    bool this_flow = false;

    switch (config->scope) {
        case CONFIG_SCOPE_PACKET:
            this_packet = true;
            break;
        case CONFIG_SCOPE_TX:
            this_tx = true;
            break;
        case CONFIG_SCOPE_FLOW:
            this_flow = true;
            break;
    }

    if (this_packet) {
        SCLogDebug("packet logic here: %" PRIu64, p->pcap_cnt);
        ConfigApplyPacket(p, config);
    } else if (this_tx) {
        SCLogDebug("tx logic here: tx_id %"PRIu64, det_ctx->tx_id);
        ConfigApplyTx(p->flow, det_ctx->tx_id, config);
    } else if (this_flow) {
        SCLogDebug("flow logic here");
    }

    SCReturnInt(0);
}

/**
 * \brief Post-match configuration detection function.
 *
 * This function is called after a match has been detected. It applies the
 * configuration settings to the packet and returns 1 indicating that the
 * configuration was successfully applied.
 *
 * \param det_ctx Pointer to the detection engine thread context.
 * \param p Pointer to the packet being processed.
 * \param s Pointer to the signature that matched.
 * \param ctx Pointer to the match context, which contains the configuration data.
 * \return 1 indicating the configuration was successfully applied
 */
static int DetectConfigPostMatch(DetectEngineThreadCtx *det_ctx,
        Packet *p, const Signature *s, const SigMatchCtx *ctx)
{
    SCEnter();
    const DetectConfigData *config = (const DetectConfigData *)ctx;
    ConfigApply(det_ctx, p, config);
    SCReturnInt(1);
}

struct ConfigStrings {
    char subsys[32];
    char state[32];
    char type[32];
    char typeval[32];
    char scope[32];
    char scopeval[32];
};

static int GetStrings(const char *str, struct ConfigStrings *p)
{
    pcre2_match_data *match = NULL;

    if (str == NULL || strlen(str) == 0) {
        SCLogError("config keywords need arguments");
        return -1;
    }
    SCLogDebug("str %s", str);

    int ret = DetectParsePcreExec(&parse_regex, &match, str, 0, 0);
    if (ret != 7) {
        SCLogError("config is rather picky at this time");
        goto error;
    }
    size_t pcre2len = sizeof(p->subsys);
    int res = pcre2_substring_copy_bynumber(match, 1, (PCRE2_UCHAR8 *)p->subsys, &pcre2len);
    if (res < 0) {
        SCLogError("failed to copy subsys substring");
        goto error;
    }

    pcre2len = sizeof(p->state);
    res = pcre2_substring_copy_bynumber(match, 2, (PCRE2_UCHAR8 *)p->state, &pcre2len);
    if (res < 0) {
        SCLogError("failed to copy state substring");
        goto error;
    }

    pcre2len = sizeof(p->type);
    res = pcre2_substring_copy_bynumber(match, 3, (PCRE2_UCHAR8 *)p->type, &pcre2len);
    if (res < 0) {
        SCLogError("failed to copy type substring");
        goto error;
    }

    pcre2len = sizeof(p->typeval);
    res = pcre2_substring_copy_bynumber(match, 4, (PCRE2_UCHAR8 *)p->typeval, &pcre2len);
    if (res < 0) {
        SCLogError("failed to copy typeval substring");
        goto error;
    }

    pcre2len = sizeof(p->scope);
    res = pcre2_substring_copy_bynumber(match, 5, (PCRE2_UCHAR8 *)p->scope, &pcre2len);
    if (res < 0) {
        SCLogError("failed to copy scope substring");
        goto error;
    }

    pcre2len = sizeof(p->scopeval);
    res = pcre2_substring_copy_bynumber(match, 6, (PCRE2_UCHAR8 *)p->scopeval, &pcre2len);
    if (res < 0) {
        SCLogError("failed to copy scopeval substring");
        goto error;
    }

    pcre2_match_data_free(match);
    return 0;
error:
    pcre2_match_data_free(match);
    return -1;
}

static bool ParseValues(const struct ConfigStrings *c, enum ConfigType *type,
        enum ConfigSubsys *subsys, enum ConfigScope *scope)
{
    SCLogDebug("subsys %s", c->subsys);
    if (strcmp(c->subsys, "logging") == 0) {
        *subsys = CONFIG_SUBSYS_LOGGING;
    } else if (strcmp(c->subsys, "tracking") == 0) {
        *subsys = CONFIG_SUBSYS_TRACKING;
    } else {
        SCLogError("invalid subsys '%s': only 'logging' and 'tracking' supported at this time",
                c->subsys);
        return false;
    }

    SCLogDebug("state %s", c->state);
    if (strcmp(c->state, "disable") != 0) {
        SCLogError("only 'disable' supported at this time");
        return false;
    }

    SCLogDebug("type %s", c->type);
    if (strcmp(c->type, "type") != 0) {
        SCLogError("only 'type' supported at this time");
        return false;
    }

    SCLogDebug("typeval %s", c->typeval);
    if (strcmp(c->typeval, "tx") == 0) {
        *type = CONFIG_TYPE_TX;
    } else if (strcmp(c->typeval, "flow") == 0) {
        *type = CONFIG_TYPE_FLOW;
    } else {
        SCLogError("only 'tx' and 'flow' supported at this time");
        return false;
    }

    SCLogDebug("scope %s", c->scope);
    if (strcmp(c->scope, "scope") != 0) {
        SCLogError("only 'scope' supported at this time");
        return false;
    }

    if (strcmp(c->scopeval, "tx") == 0) {
        *scope = CONFIG_SCOPE_TX;
    } else if (strcmp(c->scopeval, "flow") == 0) {
        *scope = CONFIG_SCOPE_FLOW;
    } else if (strcmp(c->scopeval, "packet") == 0) {
        *scope = CONFIG_SCOPE_PACKET;
    } else {
        SCLogError("invalid scope '%s': only 'tx', 'flow' and 'packet' supported at this time",
                c->scopeval);
        return false;
    }
    SCLogDebug("scopeval %s", c->scopeval);
    return true;
}

/**
 * \brief this function is used to parse config option into the current signature
 *
 * \param de_ctx pointer to the Detection Engine Context
 * \param s pointer to the Current Signature
 * \param str pointer to the user provided "config" input option string
 *
 * \retval 0 on Success
 * \retval -1 on Failure
 */
static int DetectConfigSetup(DetectEngineCtx *de_ctx, Signature *s, const char *str)
{
    SCEnter();

    struct ConfigStrings c;
    memset(&c, 0, sizeof(c));

    if (GetStrings(str, &c) != 0) {
        SCReturnInt(-1);
    }

    enum ConfigType type;
    enum ConfigSubsys subsys;
    enum ConfigScope scope;

    if (ParseValues(&c, &type, &subsys, &scope) == false) {
        SCReturnInt(-1);
    }

    /* TODO table is not yet set here */
    if (scope == CONFIG_SCOPE_PACKET && subsys == CONFIG_SUBSYS_TRACKING &&
            type == CONFIG_TYPE_FLOW) {
        if (s->init_data->hook.type != SIGNATURE_HOOK_TYPE_PKT &&
                s->init_data->hook.t.pkt.ph != SIGNATURE_HOOK_PKT_PRE_FLOW) {
            SCLogError("disabling flow tracking is only supported in 'pre_flow' hook");
            SCReturnInt(-1);
        }
    }

    DetectConfigData *fd = SCCalloc(1, sizeof(DetectConfigData));
    if (unlikely(fd == NULL))
        return -1;

    fd->type = type;
    fd->scope = scope;
    fd->subsys = subsys;

    if (fd->scope == CONFIG_SCOPE_TX) {
        s->flags |= SIG_FLAG_APPLAYER;
    }

    if (SCSigMatchAppendSMToList(
                de_ctx, s, DETECT_CONFIG, (SigMatchCtx *)fd, DETECT_SM_LIST_POSTMATCH) == NULL) {
        return -1;
    }

    return 0;
}

static void DetectConfigFree(DetectEngineCtx *de_ctx, void *ptr)
{
    if (ptr != NULL) {
        SCFree(ptr);
    }
}

#ifdef UNITTESTS
static int DetectConfigTest01(void)
{
    DetectEngineCtx *de_ctx = DetectEngineCtxInit();
    FAIL_IF(de_ctx == NULL);
    de_ctx->flags |= DE_QUIET;
    Signature *s = DetectEngineAppendSig(de_ctx,
            "config dns any any -> any any ("
            "dns.query; content:\"common.domain.com\"; "
            "config:logging disable, type tx, scope tx; "
            "sid:1;)");
    FAIL_IF_NULL(s);
    DetectEngineCtxFree(de_ctx);
    PASS;
}

void DetectConfigRegisterTests(void)
{
    UtRegisterTest("DetectConfigTest01", DetectConfigTest01);
}
#endif /* UNITTESTS */

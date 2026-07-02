/* Copyright (C) 2014 Open Information Security Foundation
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
 * \author Ignacio Sanchez <sanchezmartin.ji@gmail.com>
 * \author Duarte Silva <duarte.silva@serializing.me>
 */

#include "suricata-common.h"
#include "conf.h"

#include "app-layer-parser.h"
#include "app-layer-htp.h"
#include "app-layer-htp-xff.h"

#include "util-misc.h"
#include "util-unittest.h"

/** Default XFF header name */
#define XFF_DEFAULT "X-Forwarded-For"

static int HttpXFFGetIPFromTxAux(htp_tx_t *tx, HttpXFFCfg *xff_cfg, char *dstbuf, int dstbuflen)
{
    return htp_xff_get_ip(
            tx, xff_cfg->flags & XFF_REVERSE, xff_cfg->header, (uint8_t *)dstbuf, dstbuflen);
}

/**
 * \brief Function to return XFF IP if any in the selected transaction. The
 * caller needs to lock the flow.
 * \retval 1 if the IP has been found and returned in dstbuf
 * \retval 0 if the IP has not being found or error
 */
int HttpXFFGetIPFromTx(
        const Flow *f, uint64_t tx_id, HttpXFFCfg *xff_cfg, char *dstbuf, int dstbuflen)
{
    HtpState *htp_state = NULL;
    uint64_t total_txs = 0;
    htp_tx_t *tx = NULL;

    htp_state = (HtpState *)FlowGetAppState(f);

    if (htp_state == NULL) {
        SCLogDebug("no http state, XFF IP cannot be retrieved");
        return 0;
    }

    total_txs = AppLayerParserGetTxCnt(f, htp_state);
    if (tx_id >= total_txs)
        return 0;

    tx = AppLayerParserGetTx(f->proto, ALPROTO_HTTP1, htp_state, tx_id);
    if (tx == NULL) {
        SCLogDebug("tx is NULL, XFF cannot be retrieved");
        return 0;
    }
    return HttpXFFGetIPFromTxAux(tx, xff_cfg, dstbuf, dstbuflen);
}

/**
 *  \brief Function to return XFF IP if any. The caller needs to lock the flow.
 *  \retval 1 if the IP has been found and returned in dstbuf
 *  \retval 0 if the IP has not being found or error
 */
int HttpXFFGetIP(const Flow *f, HttpXFFCfg *xff_cfg, char *dstbuf, int dstbuflen)
{
    HtpState *htp_state = (HtpState *)FlowGetAppState(f);
    if (htp_state == NULL) {
        SCLogDebug("no http state, XFF IP cannot be retrieved");
        goto end;
    }

    uint64_t tx_id = AppLayerParserGetMinId(f->alparser);
    const uint64_t total_txs = AppLayerParserGetTxCnt(f, htp_state);
    AppLayerGetTxIteratorFunc IterFunc = AppLayerGetTxIterator(f->proto, f->alproto);
    AppLayerGetTxIterState state;
    memset(&state, 0, sizeof(state));

    while (1) {
        AppLayerGetTxIterTuple ires =
                IterFunc(f->proto, f->alproto, f->alstate, tx_id, total_txs, &state);
        if (ires.tx_ptr == NULL)
            break;

        if (HttpXFFGetIPFromTxAux(ires.tx_ptr, xff_cfg, dstbuf, dstbuflen) == 1)
            return 1;

        tx_id = ires.tx_id + 1;
    }

end:
    return 0; // Not found
}

/**
 * \brief Function to return XFF configuration from a configuration node.
 */
void HttpXFFGetCfg(SCConfNode *conf, HttpXFFCfg *result)
{
    BUG_ON(result == NULL);

    SCConfNode *xff_node = NULL;

    if (conf != NULL)
        xff_node = SCConfNodeLookupChild(conf, "xff");

    if (xff_node != NULL && SCConfNodeChildValueIsTrue(xff_node, "enabled")) {
        const char *xff_mode = SCConfNodeLookupChildValue(xff_node, "mode");

        if (xff_mode != NULL && strcasecmp(xff_mode, "overwrite") == 0) {
            result->flags |= XFF_OVERWRITE;
        } else {
            if (xff_mode == NULL) {
                SCLogWarning("The XFF mode hasn't been defined, falling back to extra-data mode");
            }
            else if (strcasecmp(xff_mode, "extra-data") != 0) {
                SCLogWarning(
                        "The XFF mode %s is invalid, falling back to extra-data mode", xff_mode);
            }
            result->flags |= XFF_EXTRADATA;
        }

        const char *xff_deployment = SCConfNodeLookupChildValue(xff_node, "deployment");

        if (xff_deployment != NULL && strcasecmp(xff_deployment, "forward") == 0) {
            result->flags |= XFF_FORWARD;
        } else {
            if (xff_deployment == NULL) {
                SCLogWarning("The XFF deployment hasn't been defined, falling back to reverse "
                             "proxy deployment");
            }
            else if (strcasecmp(xff_deployment, "reverse") != 0) {
                SCLogWarning("The XFF mode %s is invalid, falling back to reverse proxy deployment",
                        xff_deployment);
            }
            result->flags |= XFF_REVERSE;
        }

        const char *xff_header = SCConfNodeLookupChildValue(xff_node, "header");

        if (xff_header != NULL) {
            result->header = (char *) xff_header;
        } else {
            SCLogWarning("The XFF header hasn't been defined, using the default %s", XFF_DEFAULT);
            result->header = XFF_DEFAULT;
        }
    } else {
        result->flags = XFF_DISABLED;
    }
}

#ifdef UNITTESTS
static int XFFTest07(void) {
    char input[] = "1.2.3.4";
    char output[46];
    int r = ParseXFFString(input, output, sizeof(output));
    FAIL_IF_NOT(r == 1 && strcmp(output, "1.2.3.4") == 0);
    PASS;
}

static int XFFTest08(void) {
    char input[] = "[1.2.3.4:1234";
    char output[46];
    int r = ParseXFFString(input, output, sizeof(output));
    FAIL_IF_NOT(r == 0);
    PASS;
}

static int XFFTest09(void) {
    char input[] = "999.999.999.999:1234";
    char output[46];
    int r = ParseXFFString(input, output, sizeof(output));
    FAIL_IF_NOT(r == 0);
    PASS;
}

#endif

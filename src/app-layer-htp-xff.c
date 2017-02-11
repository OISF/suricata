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
#include "util-memrchr.h"
#include "util-unittest.h"

/** XFF header value minimal length */
#define XFF_CHAIN_MINLEN 7
/** XFF header value maximum length */
#define XFF_CHAIN_MAXLEN 256
/** Default XFF header name */
#define XFF_DEFAULT "X-Forwarded-For"

/** \internal
 *  \brief parse XFF string
 *  \param input input string, might be modified
 *  \param output output buffer
 *  \param output_size size of output buffer
 *  \retval bool 1 ok, 0 fail
 */
static int ParseXFFString(char *input, char *output, int output_size)
{
    size_t len = strlen(input);
    if (len == 0)
        return 0;

    if (input[0] == '[') {
        char *end = strchr(input, ']');
        if (end == NULL) // malformed, not closed
            return 0;

        if (end != input+(len - 1)) {
            SCLogDebug("data after closing bracket");
            // if we ever want to parse the port, we can do it here
        }

        /* done, lets wrap up */
        input++;        // skip past [
        *end = '\0';    // overwrite ], ignore anything after

    } else {
        /* lets see if the xff string ends in a port */
        int c = 0;
        int d = 0;
        char *p = input;
        while (*p != '\0') {
            if (*p == ':')
                c++;
            if (*p == '.')
                d++;
            p++;
        }
        /* 3 dots: ipv4, one ':' port */
        if (d == 3 && c == 1) {
            SCLogDebug("XFF w port %s", input);
            char *x = strchr(input, ':');
            if (x) {
                *x = '\0';
                SCLogDebug("XFF w/o port %s", input);
                // if we ever want to parse the port, we can do it here
            }
        }
    }

    SCLogDebug("XFF %s", input);

    /** Sanity check on extracted IP for IPv4 and IPv6 */
    uint32_t ip[4];
    if (inet_pton(AF_INET,  input, ip) == 1 ||
        inet_pton(AF_INET6, input, ip) == 1)
    {
        strlcpy(output, input, output_size);
        return 1; // OK
    }
    return 0;
}

/**
 * \brief Function to return XFF IP if any in the selected transaction. The
 * caller needs to lock the flow.
 * \retval 1 if the IP has been found and returned in dstbuf
 * \retval 0 if the IP has not being found or error
 */
int HttpXFFGetIPFromTx(const Packet *p, uint64_t tx_id, HttpXFFCfg *xff_cfg,
        char *dstbuf, int dstbuflen)
{
    uint8_t xff_chain[XFF_CHAIN_MAXLEN];
    HtpState *htp_state = NULL;
    htp_tx_t *tx = NULL;
    uint64_t total_txs = 0;
    uint8_t *p_xff = NULL;

    htp_state = (HtpState *)FlowGetAppState(p->flow);

    if (htp_state == NULL) {
        SCLogDebug("no http state, XFF IP cannot be retrieved");
        return 0;
    }

    total_txs = AppLayerParserGetTxCnt(p->flow, htp_state);
    if (tx_id >= total_txs)
        return 0;

    tx = AppLayerParserGetTx(p->flow->proto, ALPROTO_HTTP, htp_state, tx_id);
    if (tx == NULL) {
        SCLogDebug("tx is NULL, XFF cannot be retrieved");
        return 0;
    }

    htp_header_t *h_xff = NULL;
    if (tx->request_headers != NULL) {
        h_xff = htp_table_get_c(tx->request_headers, xff_cfg->header);
    }

    if (h_xff != NULL && bstr_len(h_xff->value) >= XFF_CHAIN_MINLEN &&
            bstr_len(h_xff->value) < XFF_CHAIN_MAXLEN) {

        memcpy(xff_chain, bstr_ptr(h_xff->value), bstr_len(h_xff->value));
        xff_chain[bstr_len(h_xff->value)]=0;

        if (xff_cfg->flags & XFF_REVERSE) {
            /** Get the last IP address from the chain */
            p_xff = memrchr(xff_chain, ' ', bstr_len(h_xff->value));
            if (p_xff == NULL) {
                p_xff = xff_chain;
            } else {
                p_xff++;
            }
        }
        else {
            /** Get the first IP address from the chain */
            p_xff = memchr(xff_chain, ',', bstr_len(h_xff->value));
            if (p_xff != NULL) {
                *p_xff = 0;
            }
            p_xff = xff_chain;
        }
        return ParseXFFString((char *)p_xff, dstbuf, dstbuflen);
    }
    return 0;
}

/**
 *  \brief Function to return XFF IP if any. The caller needs to lock the flow.
 *  \retval 1 if the IP has been found and returned in dstbuf
 *  \retval 0 if the IP has not being found or error
 */
int HttpXFFGetIP(const Packet *p, HttpXFFCfg *xff_cfg, char *dstbuf, int dstbuflen)
{
    HtpState *htp_state = NULL;
    uint64_t tx_id = 0;
    uint64_t total_txs = 0;

    htp_state = (HtpState *)FlowGetAppState(p->flow);
    if (htp_state == NULL) {
        SCLogDebug("no http state, XFF IP cannot be retrieved");
        goto end;
    }

    total_txs = AppLayerParserGetTxCnt(p->flow, htp_state);
    for (; tx_id < total_txs; tx_id++) {
        if (HttpXFFGetIPFromTx(p, tx_id, xff_cfg, dstbuf, dstbuflen) == 1)
            return 1;
    }

end:
    return 0; // Not found
}

/**
 * \brief Function to return XFF configuration from a configuration node.
 */
void HttpXFFGetCfg(ConfNode *conf, HttpXFFCfg *result)
{
    BUG_ON(conf == NULL || result == NULL);

    ConfNode *xff_node = NULL;

    if (conf != NULL)
        xff_node = ConfNodeLookupChild(conf, "xff");

    if (xff_node != NULL && ConfNodeChildValueIsTrue(xff_node, "enabled")) {
        const char *xff_mode = ConfNodeLookupChildValue(xff_node, "mode");

        if (xff_mode != NULL && strcasecmp(xff_mode, "overwrite") == 0) {
            result->flags |= XFF_OVERWRITE;
        } else {
            if (xff_mode == NULL) {
                SCLogWarning(SC_WARN_XFF_INVALID_MODE, "The XFF mode hasn't been defined, falling back to extra-data mode");
            }
            else if (strcasecmp(xff_mode, "extra-data") != 0) {
                SCLogWarning(SC_WARN_XFF_INVALID_MODE, "The XFF mode %s is invalid, falling back to extra-data mode",
                        xff_mode);
            }
            result->flags |= XFF_EXTRADATA;
        }

        const char *xff_deployment = ConfNodeLookupChildValue(xff_node, "deployment");

        if (xff_deployment != NULL && strcasecmp(xff_deployment, "forward") == 0) {
            result->flags |= XFF_FORWARD;
        } else {
            if (xff_deployment == NULL) {
                SCLogWarning(SC_WARN_XFF_INVALID_DEPLOYMENT, "The XFF deployment hasn't been defined, falling back to reverse proxy deployment");
            }
            else if (strcasecmp(xff_deployment, "reverse") != 0) {
                SCLogWarning(SC_WARN_XFF_INVALID_DEPLOYMENT, "The XFF mode %s is invalid, falling back to reverse proxy deployment",
                        xff_deployment);
            }
            result->flags |= XFF_REVERSE;
        }

        const char *xff_header = ConfNodeLookupChildValue(xff_node, "header");

        if (xff_header != NULL) {
            result->header = (char *) xff_header;
        } else {
            SCLogWarning(SC_WARN_XFF_INVALID_HEADER, "The XFF header hasn't been defined, using the default %s",
                    XFF_DEFAULT);
            result->header = XFF_DEFAULT;
        }
    }
    else {
        result->flags = XFF_DISABLED;
    }
}


#ifdef UNITTESTS
static int XFFTest01(void) {
    char input[] = "1.2.3.4:5678";
    char output[16];
    int r = ParseXFFString(input, output, sizeof(output));
    if (r == 1 && strcmp(output, "1.2.3.4") == 0) {
        return 1;
    }
    return 0;
}

static int XFFTest02(void) {
    char input[] = "[12::34]:1234"; // thanks chort!
    char output[16];
    int r = ParseXFFString(input, output, sizeof(output));
    if (r == 1 && strcmp(output, "12::34") == 0) {
        return 1;
    }
    return 0;
}

static int XFFTest03(void) {
    char input[] = "[2a03:2880:1010:3f02:face:b00c:0:2]:80"; // thanks chort!
    char output[46];
    int r = ParseXFFString(input, output, sizeof(output));
    if (r == 1 && strcmp(output, "2a03:2880:1010:3f02:face:b00c:0:2") == 0) {
        return 1;
    }
    return 0;
}

static int XFFTest04(void) {
    char input[] = "[2a03:2880:1010:3f02:face:b00c:0:2]"; // thanks chort!
    char output[46];
    int r = ParseXFFString(input, output, sizeof(output));
    if (r == 1 && strcmp(output, "2a03:2880:1010:3f02:face:b00c:0:2") == 0) {
        return 1;
    }
    return 0;
}

static int XFFTest05(void) {
    char input[] = "[::ffff:1.2.3.4]:1234"; // thanks double-p
    char output[46];
    int r = ParseXFFString(input, output, sizeof(output));
    if (r == 1 && strcmp(output, "::ffff:1.2.3.4") == 0) {
        return 1;
    }
    return 0;
}

static int XFFTest06(void) {
    char input[] = "12::34";
    char output[46];
    int r = ParseXFFString(input, output, sizeof(output));
    if (r == 1 && strcmp(output, "12::34") == 0) {
        return 1;
    }
    return 0;
}

static int XFFTest07(void) {
    char input[] = "1.2.3.4";
    char output[46];
    int r = ParseXFFString(input, output, sizeof(output));
    if (r == 1 && strcmp(output, "1.2.3.4") == 0) {
        return 1;
    }
    return 0;
}

static int XFFTest08(void) {
    char input[] = "[1.2.3.4:1234";
    char output[46];
    int r = ParseXFFString(input, output, sizeof(output));
    if (r == 0) {
        return 1;
    }
    return 0;
}

static int XFFTest09(void) {
    char input[] = "999.999.999.999:1234";
    char output[46];
    int r = ParseXFFString(input, output, sizeof(output));
    if (r == 0) {
        return 1;
    }
    return 0;
}

#endif

void HTPXFFParserRegisterTests(void)
{
#ifdef UNITTESTS
    UtRegisterTest("XFFTest01", XFFTest01);
    UtRegisterTest("XFFTest02", XFFTest02);
    UtRegisterTest("XFFTest03", XFFTest03);
    UtRegisterTest("XFFTest04", XFFTest04);
    UtRegisterTest("XFFTest05", XFFTest05);
    UtRegisterTest("XFFTest06", XFFTest06);
    UtRegisterTest("XFFTest07", XFFTest07);
    UtRegisterTest("XFFTest08", XFFTest08);
    UtRegisterTest("XFFTest09", XFFTest09);
#endif
}

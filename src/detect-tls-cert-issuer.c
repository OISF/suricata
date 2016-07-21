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
 * \file
 *
 * \author Mats Klepsland <mats.klepsland@gmail.com>
 *
 * Implements support for tls_cert_issuer keyword.
 */

#include "suricata-common.h"
#include "threads.h"
#include "debug.h"
#include "decode.h"
#include "detect.h"

#include "detect-parse.h"
#include "detect-engine.h"
#include "detect-engine-mpm.h"
#include "detect-content.h"
#include "detect-pcre.h"

#include "flow.h"
#include "flow-util.h"
#include "flow-var.h"

#include "util-debug.h"
#include "util-unittest.h"
#include "util-spm.h"
#include "util-print.h"

#include "stream-tcp.h"

#include "app-layer.h"
#include "app-layer-ssl.h"

#include "util-unittest.h"
#include "util-unittest-helper.h"

static int DetectTlsIssuerSetup(DetectEngineCtx *, Signature *, char *);
static void DetectTlsIssuerRegisterTests(void);

/**
 * \brief Registration function for keyword: tls_cert_issuer
 */
void DetectTlsIssuerRegister(void)
{
    sigmatch_table[DETECT_AL_TLS_CERT_ISSUER].name = "tls_cert_issuer";
    sigmatch_table[DETECT_AL_TLS_CERT_ISSUER].desc = "content modifier to match specifically and only on the TLS cert issuer buffer";
    sigmatch_table[DETECT_AL_TLS_CERT_ISSUER].Match = NULL;
    sigmatch_table[DETECT_AL_TLS_CERT_ISSUER].AppLayerMatch = NULL;
    sigmatch_table[DETECT_AL_TLS_CERT_ISSUER].alproto = ALPROTO_TLS;
    sigmatch_table[DETECT_AL_TLS_CERT_ISSUER].Setup = DetectTlsIssuerSetup;
    sigmatch_table[DETECT_AL_TLS_CERT_ISSUER].Free  = NULL;
    sigmatch_table[DETECT_AL_TLS_CERT_ISSUER].RegisterTests = DetectTlsIssuerRegisterTests;

    sigmatch_table[DETECT_AL_TLS_CERT_ISSUER].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_AL_TLS_CERT_ISSUER].flags |= SIGMATCH_PAYLOAD;
}


/**
 * \brief this function setup the tls_cert_issuer modifier keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval 0       On success
 */
static int DetectTlsIssuerSetup(DetectEngineCtx *de_ctx, Signature *s, char *str)
{
    s->list = DETECT_SM_LIST_TLSISSUER_MATCH;
    s->alproto = ALPROTO_TLS;
    return 0;
}

#ifdef UNITTESTS
    /* TODO add unit tests */
#endif

static void DetectTlsIssuerRegisterTests(void)
{
#ifdef UNITTESTS
    /* TODO add unit tests */
#endif
}

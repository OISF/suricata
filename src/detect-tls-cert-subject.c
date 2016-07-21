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
 * Implements support for tls_cert_subject keyword.
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

static int DetectTlsSubjectSetup(DetectEngineCtx *, Signature *, char *);
static void DetectTlsSubjectRegisterTests(void);

/**
 * \brief Registration function for keyword: tls_cert_issuer
 */
void DetectTlsSubjectRegister(void)
{
    sigmatch_table[DETECT_AL_TLS_CERT_SUBJECT].name = "tls_cert_subject";
    sigmatch_table[DETECT_AL_TLS_CERT_SUBJECT].desc = "content modifier to match specifically and only on the TLS cert subject buffer";
    sigmatch_table[DETECT_AL_TLS_CERT_SUBJECT].Match = NULL;
    sigmatch_table[DETECT_AL_TLS_CERT_SUBJECT].AppLayerMatch = NULL;
    sigmatch_table[DETECT_AL_TLS_CERT_SUBJECT].alproto = ALPROTO_TLS;
    sigmatch_table[DETECT_AL_TLS_CERT_SUBJECT].Setup = DetectTlsSubjectSetup;
    sigmatch_table[DETECT_AL_TLS_CERT_SUBJECT].Free  = NULL;
    sigmatch_table[DETECT_AL_TLS_CERT_SUBJECT].RegisterTests = DetectTlsSubjectRegisterTests;

    sigmatch_table[DETECT_AL_TLS_CERT_SUBJECT].flags |= SIGMATCH_NOOPT;
    sigmatch_table[DETECT_AL_TLS_CERT_SUBJECT].flags |= SIGMATCH_PAYLOAD;
}

/**
 * \brief this function setup the tls_cert_subject modifier keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval 0       On success
 */
static int DetectTlsSubjectSetup(DetectEngineCtx *de_ctx, Signature *s, char *str)
{
    s->list = DETECT_SM_LIST_TLSSUBJECT_MATCH;
    s->alproto = ALPROTO_TLS;
    return 0;
}

#ifdef UNITTESTS
    /* TODO add unit tests */
#endif

static void DetectTlsSubjectRegisterTests(void)
{
#ifdef UNITTESTS
    /* TODO add unit tests */
#endif
}

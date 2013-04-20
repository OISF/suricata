/* Copyright (C) 2013 Open Information Security Foundation
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
 * \ingroup dnslayer
 *
 * @{
 */


/**
 * \file
 *
 * \author Victor Julien <victor@inliniac.net>
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
#include "flow-var.h"

#include "util-debug.h"
#include "util-unittest.h"
#include "util-spm.h"
#include "util-print.h"

#include "app-layer.h"

#include "detect-dns-query.h"

static int DetectDnsQuerySetup (DetectEngineCtx *, Signature *, char *);

/**
 * \brief Registration function for keyword: http_uri
 */
void DetectDnsQueryRegister (void) {
    sigmatch_table[DETECT_AL_DNS_QUERY].name = "dns_query";
    sigmatch_table[DETECT_AL_DNS_QUERY].desc = "content modifier to match specifically and only on the DNS query-buffer";
    sigmatch_table[DETECT_AL_DNS_QUERY].Match = NULL;
    sigmatch_table[DETECT_AL_DNS_QUERY].AppLayerMatch = NULL;
    sigmatch_table[DETECT_AL_DNS_QUERY].alproto = ALPROTO_DNS;
    sigmatch_table[DETECT_AL_DNS_QUERY].Setup = DetectDnsQuerySetup;
    sigmatch_table[DETECT_AL_DNS_QUERY].Free  = NULL;
    sigmatch_table[DETECT_AL_DNS_QUERY].RegisterTests = NULL;

    sigmatch_table[DETECT_AL_DNS_QUERY].flags |= SIGMATCH_PAYLOAD;
}


/**
 * \brief this function setups the dns_query modifier keyword used in the rule
 *
 * \param de_ctx   Pointer to the Detection Engine Context
 * \param s        Pointer to the Signature to which the current keyword belongs
 * \param str      Should hold an empty string always
 *
 * \retval  0 On success
 * \retval -1 On failure
 */

static int DetectDnsQuerySetup(DetectEngineCtx *de_ctx, Signature *s, char *str)
{
    return DetectEngineContentModifierBufferSetup(de_ctx, s, str,
                                                  DETECT_AL_DNS_QUERY,
                                                  DETECT_SM_LIST_DNSQUERY_MATCH,
                                                  ALPROTO_DNS, NULL);
}

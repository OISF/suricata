/* Copyright (C) 2007-2012 Open Information Security Foundation
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
 * \author David Abarbanel <david.abarbanel@baesystems.com>
 *
 */

#ifndef __UTIL_BASE64_H_
#define __UTIL_BASE64_H_

#include "suricata-common.h"
#include "threads.h"
#include "debug.h"
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

/* Constants */
#define ASCII_BLOCK         3
#define B64_BLOCK           4

typedef enum {
    BASE64_MODE_RELAX,
    /* If the following strings were to be passed to the decoder with RFC2045 mode,
     * the results would be as follows. See the unittest B64TestVectorsRFC2045 in
     * src/util-base64.c
     *
     * BASE64("") = ""
     * BASE64("f") = "Zg=="
     * BASE64("fo") = "Zm8="
     * BASE64("foo") = "Zm9v"
     * BASE64("foob") = "Zm9vYg=="
     * BASE64("fooba") = "Zm9vYmE="
     * BASE64("foobar") = "Zm9vYmFy"
     * BASE64("foobar") = "Zm 9v Ym Fy"   <-- Notice how the spaces are ignored
     * BASE64("f") = "Zm$9vYm.Fy"    # TODO according to RFC, All line breaks or *other characters*
     * not found in base64 alphabet must be ignored by decoding software
     * */
    BASE64_MODE_RFC2045, /* SPs are allowed during transfer but must be skipped by Decoder */
    BASE64_MODE_STRICT,
    /* If the following strings were to be passed to the decoder with RFC4648 mode,
     * the results would be as follows. See the unittest B64TestVectorsRFC4648 in
     * src/util-base64.c
     *
     * BASE64("") = ""
     * BASE64("f") = "Zg=="
     * BASE64("fo") = "Zm8="
     * BASE64("foo") = "Zm9v"
     * BASE64("foob") = "Zm9vYg=="
     * BASE64("fooba") = "Zm9vYmE="
     * BASE64("foobar") = "Zm9vYmFy"
     * BASE64("f") = "Zm 9v Ym Fy"   <-- Notice how the processing stops once space is encountered
     * BASE64("f") = "Zm$9vYm.Fy"    <-- Notice how the processing stops once an invalid char is
     * encountered
     * */
    BASE64_MODE_RFC4648, /* reject the encoded data if it contains characters outside the base
                            alphabet */
} Base64Mode;

typedef enum {
    BASE64_ECODE_ERR = -1,
    BASE64_ECODE_OK = 0,
    BASE64_ECODE_BUF,
} Base64Ecode;

/* Function prototypes */
Base64Ecode DecodeBase64(uint8_t *dest, uint32_t dest_size, const uint8_t *src, uint32_t len,
        uint32_t *consumed_bytes, uint32_t *decoded_bytes, Base64Mode mode);

#endif

#ifdef UNITTESTS
void Base64RegisterTests(void);
#endif

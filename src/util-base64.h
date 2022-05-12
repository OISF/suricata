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
    BASE64_MODE_RFC2045, /* SPs are allowed during transfer but must be skipped by Decoder */
    BASE64_MODE_STRICT,
} Base64Mode;

/* Function prototypes */
uint32_t DecodeBase64(uint8_t *dest, const uint8_t *src, uint32_t len, Base64Mode mode);

#endif

#ifdef UNITTESTS
void Base64RegisterTests(void);
#endif

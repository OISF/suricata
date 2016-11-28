/* Copyright (C) 2017 Open Information Security Foundation
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
 * \author Paulo Pacheco <fooinha@gmail.com>
 *
 */

#ifndef __APP_LAYER_TLS_CIPHER_SUITE_H__
#define __APP_LAYER_TLS_CIPHER_SUITE_H__

#include "suricata-common.h"

typedef struct SSLCipherSuite_ {
    uint16_t value;
    const char *description;
} SSLCipherSuite;

const char *SSLCipherSuiteDescription(uint16_t value);
uint16_t SSLCipherSuiteByteOrderValue(uint16_t value);
SSLCipherSuite *SSLCipherSuites(size_t *len);

void SSLLoadCipherSuitesFile(const char *cipher_suites_filename);
void DetectTlsCipherSuiteRegister(void);

#endif /* __APP_LAYER_TLS_CIPHER_SUITE_H__ */

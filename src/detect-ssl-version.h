/* Copyright (C) 2007-2010 Open Information Security Foundation
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
 * \file   detect-ssl-version.h
 *
 * \author Gurvinder Singh <gurvindersinghdahiya@gmail.com>
 *
 */

#ifndef DETECT_SSL_VERSION_H
#define	DETECT_SSL_VERSION_H

#define DETECT_SSL_VERSION_NEGATED   0x01

#define SSLv2   0
#define SSLv3   1
#define TLS10   2
#define TLS11   3
#define TLS12   4

typedef struct SSLVersionData_ {
    uint16_t ver; /** ssl version to match */
    uint8_t flags;
}SSLVersionData;

typedef struct DetectSslVersionData_ {
    SSLVersionData data[5];
} DetectSslVersionData;

/* prototypes */
void DetectSslVersionRegister (void);

#endif	/* DETECT_SSL_VERSION_H */

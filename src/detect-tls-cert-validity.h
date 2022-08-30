/* Copyright (C) 2022 Open Information Security Foundation
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
 */

#ifndef __DETECT_TLS_VALIDITY_H__
#define __DETECT_TLS_VALIDITY_H__

#define DETECT_TLS_VALIDITY_EQ (1)    /* equal */
#define DETECT_TLS_VALIDITY_LT (1<<1) /* less than */
#define DETECT_TLS_VALIDITY_GT (1<<2) /* greater than */
#define DETECT_TLS_VALIDITY_RA (1<<3) /* range */

/* Used by tls_cert_expired */
#define DETECT_TLS_VALIDITY_EX (1<<4) /* expired */

/* Used by tls_cert_valid */
#define DETECT_TLS_VALIDITY_VA (1<<5) /* valid */

#define DETECT_TLS_TYPE_NOTBEFORE 0
#define DETECT_TLS_TYPE_NOTAFTER  1

typedef struct DetectTlsValidityData_ {
    time_t epoch;
    time_t epoch2;
    uint8_t mode;
    uint8_t type;
} DetectTlsValidityData;

/* prototypes */
void DetectTlsValidityRegister (void);

#endif /* __DETECT_TLS_VALIDITY_H__ */

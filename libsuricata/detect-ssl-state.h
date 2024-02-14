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
 * \file
 *
 * \author Anoop Saldanha <anoopsaldanha@gmail.com>
 */

#ifndef DETECT_SSL_STATE_H
#define	DETECT_SSL_STATE_H

/* we pick these flags from the parser */
#define DETECT_SSL_STATE_CLIENT_HELLO SSL_AL_FLAG_STATE_CLIENT_HELLO
#define DETECT_SSL_STATE_SERVER_HELLO SSL_AL_FLAG_STATE_SERVER_HELLO
#define DETECT_SSL_STATE_CLIENT_KEYX  SSL_AL_FLAG_STATE_CLIENT_KEYX
#define DETECT_SSL_STATE_SERVER_KEYX  SSL_AL_FLAG_STATE_SERVER_KEYX
#define DETECT_SSL_STATE_UNKNOWN      SSL_AL_FLAG_STATE_UNKNOWN

typedef struct DetectSslStateData_ {
    uint32_t flags;
    uint32_t mask;
} DetectSslStateData;

void DetectSslStateRegister(void);

#endif /* DETECT_SSL_STATE_H */

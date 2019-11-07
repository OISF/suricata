/* Copyright (C) 2015 Open Information Security Foundation
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
 * \author Pierre Chifflier <chifflier@wzdftpd.net>
 */

#ifndef __APP_LAYER_IKEV2_H__
#define __APP_LAYER_IKEV2_H__

void RegisterIKEV2Parsers(void);

/** Opaque Rust types. */
typedef struct IKEV2State_ IKEV2State;
typedef struct IKEV2Transaction_ IKEV2Transaction;

#endif /* __APP_LAYER_IKEV2_H__ */

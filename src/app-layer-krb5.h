/* Copyright (C) 2015-2022 Open Information Security Foundation
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

#ifndef __APP_LAYER_KRB5_H__
#define __APP_LAYER_KRB5_H__

void RegisterKRB5Parsers(void);
void KRB5ParserRegisterTests(void);

/** Opaque Rust types. */
typedef struct KRB5State_ KRB5State;
typedef struct KRB5Transaction_ KRB5Transaction;

#endif /* __APP_LAYER_KRB5_H__ */

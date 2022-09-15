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

#ifndef __RUST_H__
#define __RUST_H__

#include "util-lua.h"
// hack for include orders cf SCSha256
typedef struct HttpRangeContainerBlock HttpRangeContainerBlock;
#include "rust-context.h"
#include "rust-bindings.h"

/* Some manual exports from Rust as we are not yet exporting constants with
 * cbindgen. */
#define SC_MD5_LEN    16
#define SC_SHA1_LEN   20
#define SC_SHA256_LEN 32

/* Length of an MD5 hex string, not including a trailing NUL. */
#define SC_MD5_HEX_LEN 32

#define JB_SET_STRING(jb, key, val) jb_set_formatted((jb), "\"" key "\":\"" val "\"")
#define JB_SET_TRUE(jb, key) jb_set_formatted((jb), "\"" key "\":true")
#define JB_SET_FALSE(jb, key) jb_set_formatted((jb), "\"" key "\":false")

#endif /* !__RUST_H__ */

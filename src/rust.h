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

#ifndef SURICATA_RUST_H
#define SURICATA_RUST_H

// Forward declarations needed by rust-bindings.h
typedef struct HttpRangeContainerBlock HttpRangeContainerBlock;

// These need to be removed by making rust using a generic void
// in functions prototypes and then casting
typedef struct IKEState_ IKEState;
typedef struct IKETransaction_ IKETransaction;
typedef struct TFTPState_ TFTPState;
typedef struct TFTPTransaction_ TFTPTransaction;

typedef struct DetectEngineState_ DetectEngineState;

// may be improved by smaller include
#include "detect.h"

#include "rust-bindings.h"

#define JB_SET_STRING(jb, key, val) SCJbSetFormatted((jb), "\"" key "\":\"" val "\"")
#define JB_SET_TRUE(jb, key)        SCJbSetFormatted((jb), "\"" key "\":true")
#define JB_SET_FALSE(jb, key)       SCJbSetFormatted((jb), "\"" key "\":false")

#endif /* !SURICATA_RUST_H */

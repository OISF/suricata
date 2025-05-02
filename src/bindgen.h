/* Copyright (C) 2025 Open Information Security Foundation
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
 * \file Input to bindgen to generate Rust bindings.
 *
 * This file should include every header that should have Rust
 * bindings generated for it. It is then used by bindgen to generate
 * the Rust bindings.
 */

#ifndef SURICATA_BINDGEN_H
#define SURICATA_BINDGEN_H

#include "stdint.h"
#include "stdbool.h"

#define WARN_UNUSED

#include "app-layer-protos.h"
#include "suricata-plugin.h"
// do not export struct fields only used for debug validation
// do this after suricata-plugin.h which needs autoconf.h to define SC_PACKAGE_VERSION
#undef DEBUG_VALIDATION
#include "output-eve-bindgen.h"
#include "detect-engine-register.h"
#include "detect-engine-buffer.h"
#include "detect-engine-helper.h"

#include "conf.h"

#endif

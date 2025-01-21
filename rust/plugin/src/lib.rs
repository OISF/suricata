/* Copyright (C) 2020-2023 Open Information Security Foundation
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

 use suricata::*;

// Type definitions
pub type AppProto = core::AppProto;
pub type AppLayerEventType = core::AppLayerEventType;

// Constant definitions
pub const ALPROTO_UNKNOWN: AppProto = core::ALPROTO_UNKNOWN;
pub const IPPROTO_TCP : u8 = core::IPPROTO_TCP;

pub const APP_LAYER_PARSER_OPT_ACCEPT_GAPS : u32 = applayer::APP_LAYER_PARSER_OPT_ACCEPT_GAPS;
pub const APP_LAYER_PARSER_EOF_TC : u16 = applayer::APP_LAYER_PARSER_EOF_TC;
pub const APP_LAYER_PARSER_EOF_TS : u16 = applayer::APP_LAYER_PARSER_EOF_TS;

pub const APP_LAYER_EVENT_TYPE_TRANSACTION : AppLayerEventType = AppLayerEventType::APP_LAYER_EVENT_TYPE_TRANSACTION;

pub const SIGMATCH_NOOPT: u16 = detect::SIGMATCH_NOOPT;
pub const SIGMATCH_INFO_STICKY_BUFFER: u16 = detect::SIGMATCH_INFO_STICKY_BUFFER;
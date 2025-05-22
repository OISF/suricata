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

#[repr(C)]
pub struct SCDnsLogConfig {
    pub version: u8,
    pub flags: u64,
    pub log_additionals: bool,
    pub log_authorities: bool,
    pub answers_in_request: bool,
    pub log_opcode: bool,
    pub log_flags: bool,
    pub log_id: bool,
    pub log_tx_id: bool,
    pub log_ttl: bool,
    pub log_rcode: bool,
}

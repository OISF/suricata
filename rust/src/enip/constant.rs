/* Copyright (C) 2023 Open Information Security Foundation
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

use suricata_derive::{EnumStringU16, EnumStringU32};

#[derive(Clone, Debug, Default, EnumStringU16)]
#[repr(u16)]
pub enum EnipCommand {
    #[default]
    Nop = 0,
    ListServices = 4,
    ListIdentity = 0x63,
    ListInterfaces = 0x64,
    RegisterSession = 0x65,
    UnregisterSession = 0x66,
    SendRRData = 0x6F,
    SendUnitData = 0x70,
    IndicateStatus = 0x72,
    Cancel = 0x73,
}

#[derive(Clone, Debug, Default, EnumStringU32)]
#[repr(u32)]
pub enum EnipStatus {
    #[default]
    Success = 0,
    InvalidCmd = 1,
    NoResources = 2,
    IncorrectData = 3,
    InvalidSession = 0x64,
    InvalidLength = 0x65,
    UnsupportedProtRev = 0x69,
    //Found in wireshark
    EncapHeaderError = 0x6A,
}

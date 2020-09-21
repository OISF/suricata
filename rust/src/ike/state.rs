/* Copyright (C) 2018 Open Information Security Foundation
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

// written by Pierre Chifflier  <chifflier@wzdftpd.net>

extern crate ipsec_parser;
use self::ipsec_parser::*;

#[derive(Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum IKEV2ConnectionState {
    Init,
    InitSASent,
    InitKESent,
    InitNonceSent,
    RespSASent,
    RespKESent,
    RespNonceSent,
    RespCertReqSent,

    ParsingDone,

    Invalid,
}

impl IKEV2ConnectionState {
    pub fn advance(&self, payload: &IkeV2Payload) -> IKEV2ConnectionState {
        use self::IKEV2ConnectionState::*;
        match (self, &payload.content) {
            (&Init, &IkeV2PayloadContent::SA(_))                          => InitSASent,
            (&InitSASent, &IkeV2PayloadContent::KE(_))                    => InitKESent,
            (&InitKESent, &IkeV2PayloadContent::Nonce(_))                 => InitNonceSent,
            (&InitNonceSent, &IkeV2PayloadContent::SA(_))                 => RespSASent,
            (&RespSASent, &IkeV2PayloadContent::KE(_))                    => RespKESent,
            (&RespKESent, &IkeV2PayloadContent::Nonce(_))                 => ParsingDone, // RespNonceSent,
            (&RespNonceSent, &IkeV2PayloadContent::CertificateRequest(_)) => ParsingDone, // RespCertReqSent,
            (&ParsingDone,_)                                              => self.clone(),
            (_, &IkeV2PayloadContent::Notify(_))                          => self.clone(),
            (_, &IkeV2PayloadContent::Dummy)                              => self.clone(),
            (_,_) => Invalid,
        }
    }
}

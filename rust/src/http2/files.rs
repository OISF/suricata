/* Copyright (C) 2020 Open Information Security Foundation
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

use crate::core::*;
use crate::filecontainer::*;

/// Wrapper around Suricata's internal file container logic.
#[derive(Debug)]
pub struct HTTP2Files {
    pub files_ts: FileContainer,
    pub files_tc: FileContainer,
    pub flags_ts: u16,
    pub flags_tc: u16,
}

impl HTTP2Files {
    pub fn new() -> HTTP2Files {
        HTTP2Files {
            files_ts: FileContainer::default(),
            files_tc: FileContainer::default(),
            flags_ts: 0,
            flags_tc: 0,
        }
    }
    pub fn free(&mut self) {
        self.files_ts.free();
        self.files_tc.free();
    }

    pub fn get(&mut self, direction: u8) -> (&mut FileContainer, u16) {
        if direction == STREAM_TOSERVER {
            (&mut self.files_ts, self.flags_ts)
        } else {
            (&mut self.files_tc, self.flags_tc)
        }
    }
}

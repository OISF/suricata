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

/// LoggerFlags tracks which loggers have already been executed.
#[derive(Debug)]
pub struct LoggerFlags {
    flags: u32,
}

impl LoggerFlags {

    pub fn new() -> LoggerFlags {
        return LoggerFlags{
            flags: 0,
        }
    }

    pub fn set_logged(&mut self, logger: u32) {
        self.flags |= logger;
    }

    pub fn is_logged(&self, logger: u32) -> bool {
        self.flags & logger != 0
    }

}

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

//! Nom parsers for NFS

#[derive(Debug, PartialEq, Eq)]
pub struct NfsReplyRead<'a> {
    pub status: u32,
    pub attr_follows: u32,
    pub attr_blob: &'a [u8],
    pub count: u32,
    pub eof: bool,
    pub data_len: u32,
    pub data: &'a [u8], // likely partial
}

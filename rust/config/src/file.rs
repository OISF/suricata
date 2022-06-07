// Copyright (C) 2022 Open Information Security Foundation
//
// You can copy, redistribute or modify this Program under the terms of
// the GNU General Public License version 2 as published by the Free
// Software Foundation.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// version 2 along with this program; if not, write to the Free Software
// Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
// 02110-1301, USA.

use std::io::Read;

/// A character iterator of a file to satisfy the YAML parser that only takes a char
/// iterator. We could read the whole file into a string, but that could cause issues with
/// very large files that may be passed by accident.
pub struct FileCharIterator {
    file: std::fs::File,
}

impl FileCharIterator {
    pub fn new(file: std::fs::File) -> Self {
        Self { file }
    }

    fn next_char(&mut self) -> Option<char> {
        let mut buf: Vec<u8> = Vec::new();
        loop {
            let mut byte = [0; 1];
            match self.file.read(&mut byte) {
                Ok(n) => {
                    if n == 0 {
                        return None;
                    }
                }
                Err(_) => {
                    return None;
                }
            }
            buf.push(byte[0]);
            match String::from_utf8(buf) {
                Ok(s) => {
                    assert_eq!(s.len(), 1);
                    return s.chars().next();
                }
                Err(err) => {
                    buf = err.as_bytes().to_vec();
                    continue;
                }
            }
        }
    }
}

impl Iterator for FileCharIterator {
    type Item = char;

    fn next(&mut self) -> Option<Self::Item> {
        self.next_char()
    }
}

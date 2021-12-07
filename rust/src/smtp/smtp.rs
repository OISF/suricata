/* Copyright (C) 2021 Open Information Security Foundation
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
use crate::core::Direction;

pub struct RustSMTPBuffer {
    ts_buf: Vec<u8>,
    tc_buf: Vec<u8>,
    cur_line: Vec<u8>,
}

impl RustSMTPBuffer {

    pub fn new() -> Self {
        return Self {
            ts_buf: Vec::new(),
            tc_buf: Vec::new(),
            cur_line: Vec::new(),
        }
    }

    pub fn get_line_ts(&mut self, input: &[u8]) -> i8
    {
        // TODO Clear parser after integration
        let lf_idx = input.iter().position(|&r| r == 0x0a);
        if let Some(idx) = lf_idx {
            let idx = idx as u8;
            // TODO Set var here to indicate buffer needs clearning on next iteration
            if !self.ts_buf.is_empty() { // Last of the fragmented data
                self.ts_buf.extend_from_slice(input);
                let cr_idx = self.ts_buf.len() - 2;
                if !self.ts_buf.is_empty() && self.ts_buf[cr_idx] == 0x0d {
                    let _ = self.ts_buf.split_off(cr_idx);
                    // TODO set delimeter len to be used later
                } else {
                    self.ts_buf.pop();
                    // TODO set delimeter len to be used later
                }
                self.cur_line = self.ts_buf.clone();
            } else { // No fragments
                self.cur_line = input.to_vec();
                if idx != 0 && input[(idx - 1) as usize] == 0x0d {
                    self.cur_line.pop();
                    // TODO set delim for later
                } else {
                    // TODO set delim for later
                }
            }
        } else {
            // Possibly fragmented data, add it to buffer
            self.ts_buf.extend_from_slice(input);
            return -1
        }
        0
    }

    pub fn get_line_tc(&mut self, input: &[u8]) -> i8
    {
        // TODO Clear parser after integration
        let lf_idx = input.iter().position(|&r| r == 0x0a);
        if let Some(idx) = lf_idx {
            let idx = idx as u8;
            // TODO Set var here to indicate buffer needs clearning on next iteration
            if !self.tc_buf.is_empty() { // Last of the fragmented data
                self.tc_buf.extend_from_slice(input);
                let cr_idx = self.tc_buf.len() - 2;
                if !self.tc_buf.is_empty() && self.tc_buf[cr_idx] == 0x0d {
                    let _ = self.tc_buf.split_off(cr_idx);
                    // TODO set delimeter len to be used later
                } else {
                    self.tc_buf.pop();
                    // TODO set delimeter len to be used later
                }
                self.cur_line = self.tc_buf.clone();
            } else { // No fragmentc
                self.cur_line = input.to_vec();
                if idx != 0 && input[(idx - 1) as usize] == 0x0d {
                    self.cur_line.pop();
                    // TODO set delim for later
                } else {
                    // TODO set delim for later
                }
            }
        } else {
            // Possibly fragmented data, add it to buffer
            self.tc_buf.extend_from_slice(input);
            return -1
        }
        0
    }
}


pub unsafe extern "C" fn rs_smtp_call_getline(input: *const u8, input_len: u32, dir: u8) -> i8 {
    if input.is_null() && input_len > 0 {
        return -1;
    }
    let buf = build_slice!(input, input_len as usize);
    let mut smtp_buffer = RustSMTPBuffer::new();
    match dir.into() {
        Direction::ToServer => {
            smtp_buffer.get_line_ts(buf)
        }
        Direction::ToClient => {
            smtp_buffer.get_line_tc(buf)
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::smtp::smtp::RustSMTPBuffer;

    #[test]
    fn test_get_line_full_input() {
        // EHLO [192.168.0.158]<CR><LF>
        let line = &[0x45, 0x48, 0x4c, 0x4f, 0x20, 0x5b, 0x31, 0x39,
                    0x32, 0x2e, 0x31, 0x36, 0x38, 0x2e, 0x30, 0x2e,
                    0x31, 0x35, 0x38, 0x5d, 0x0d, 0x0a];
        let line_len = line.len();
        let mut buf = RustSMTPBuffer::new();
        let ret = buf.get_line_ts(line);
        assert_eq!(0, ret);
        assert_eq!(buf.cur_line, line[..line_len - 1]);
        assert_eq!(true, buf.ts_buf.is_empty());
    }

    #[test]
    fn test_get_line_fragmented() {
        // 250-mx.google.com at your service, [117.198.115.50]<CR><LF>
        let line1 = &[0x32, 0x35, 0x30, 0x2d, 0x6d, 0x78, 0x2e, 0x67,
                    0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x63, 0x6f,
                    0x6d, 0x20, 0x61, 0x74, 0x20, 0x79, 0x6f, 0x75];
        let line2 = &[0x72, 0x20, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63,
                    0x65, 0x2c, 0x20, 0x5b, 0x31, 0x31, 0x37, 0x2e,
                    0x31, 0x39, 0x38, 0x2e, 0x31, 0x31, 0x35, 0x2e,
                    0x35, 0x30, 0x5d, 0x0d, 0x0a];
        let mut fin_line = line1.to_vec();
        fin_line.extend_from_slice(line2);
        let fin_line_len = fin_line.len();
        let mut buf = RustSMTPBuffer::new();
        let ret = buf.get_line_tc(line1);
        assert_eq!(-1, ret);
        assert_eq!(true, buf.cur_line.is_empty());
        assert_eq!(buf.tc_buf, line1);
        let ret = buf.get_line_tc(line2);
        assert_eq!(0, ret);
        assert_eq!(false, buf.cur_line.is_empty());
        assert_eq!(buf.tc_buf, fin_line[..fin_line_len - 2]);
        assert_eq!(buf.cur_line, buf.tc_buf);
    }
}

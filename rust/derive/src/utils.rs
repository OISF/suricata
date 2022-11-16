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

/// Transform names such as "OneTwoThree" to "one_two_three".
pub fn transform_name(name: &str, delim: char) -> String {
    let mut out = String::new();
    let chars: Vec<char> = name.chars().collect();

    for i in 0..chars.len() {
        if i > 0
            && i < chars.len() - 1
            && chars[i].is_uppercase()
            && (chars[i - 1].is_lowercase() || chars[i + 1].is_lowercase())
        {
            out.push(delim);
        }
        out.push_str(&chars[i].to_lowercase().to_string());
    }
    out
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_transform_name() {
        assert_eq!(&transform_name("One", '_'), "one");
        assert_eq!(&transform_name("SomeEvent", '_'), "some_event");
        assert_eq!(
            &transform_name("UnassignedMsgType", '_'),
            "unassigned_msg_type"
        );
        assert_eq!(&transform_name("ABCName", '_'), "abc_name");
        assert_eq!(
            &transform_name("MiddleABCAcronym", '_'),
            "middle_abc_acronym"
        );
        assert_eq!(&transform_name("One", '.'), "one");
        assert_eq!(&transform_name("OneTwo", '.'), "one.two");
        assert_eq!(&transform_name("OneTwoThree", '.'), "one.two.three");
        assert_eq!(&transform_name("NBSS", '.'), "nbss");
        assert_eq!(&transform_name("NBSSHdr", '.'), "nbss.hdr");
        assert_eq!(&transform_name("SMB3Data", '.'), "smb3.data");
    }
}

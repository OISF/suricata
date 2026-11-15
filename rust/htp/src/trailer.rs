/* Copyright (C) 2026 Open Information Security Foundation
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

//! Trailer field names that RFC 9110 section 6.5.1 does not allow in a
//! trailer section: framing, routing, request modifiers, authentication,
//! response control data and payload processing.

/// Field names a sender must not put in a trailer section. Matched case
/// insensitively, so the table is lowercase.
const FORBIDDEN_FIELDS: &[&[u8]] = &[
    // framing
    b"transfer-encoding",
    b"content-length",
    b"trailer",
    // routing
    b"host",
    // request modifiers and controls
    b"cache-control",
    b"expect",
    b"max-forwards",
    b"pragma",
    b"range",
    b"te",
    b"if-match",
    b"if-none-match",
    b"if-modified-since",
    b"if-unmodified-since",
    b"if-range",
    // authentication
    b"authorization",
    b"proxy-authorization",
    b"proxy-authenticate",
    b"www-authenticate",
    // response control data
    b"age",
    b"date",
    b"expires",
    b"location",
    b"retry-after",
    b"vary",
    b"warning",
    b"allow",
    b"etag",
    b"last-modified",
    b"set-cookie",
    b"cookie",
    // payload processing
    b"content-encoding",
    b"content-type",
    b"content-range",
    b"content-disposition",
    b"content-language",
];

/// True when `name` is one of the fields RFC 9110 forbids in a trailer
/// section.
pub fn is_forbidden_field(name: &[u8]) -> bool {
    FORBIDDEN_FIELDS
        .iter()
        .any(|f| name.len() == f.len() && name.eq_ignore_ascii_case(f))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_forbidden_trailer_fields() {
        assert!(is_forbidden_field(b"Content-Length"));
        assert!(is_forbidden_field(b"CONTENT-LENGTH"));
        assert!(is_forbidden_field(b"host"));
        assert!(is_forbidden_field(b"Transfer-Encoding"));
        assert!(is_forbidden_field(b"Content-Type"));
        assert!(is_forbidden_field(b"Cookie"));
        assert!(is_forbidden_field(b"Set-Cookie"));
        assert!(!is_forbidden_field(b"Server-Timing"));
        assert!(!is_forbidden_field(b"User-Agent"));
        assert!(!is_forbidden_field(b"grpc-status"));
        assert!(!is_forbidden_field(b"Content-Lengthx"));
        assert!(!is_forbidden_field(b""));
    }
}

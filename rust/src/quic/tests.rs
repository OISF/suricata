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

use super::QuicState;
use crate::encryption::EncryptionHandling;
use crate::quic::crypto::test_packets::{initial, retry};
use std::{ptr, time::Duration};

fn hello(name: &str) -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend([0; 32]);
    body.extend([0, 0, 2, 0x13, 1, 1, 0]); // session, cipher, compression
    let mut sni = ((name.len() + 3) as u16).to_be_bytes().to_vec();
    sni.push(0);
    sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
    sni.extend_from_slice(name.as_bytes());
    let mut ext = vec![0, 0];
    ext.extend_from_slice(&(sni.len() as u16).to_be_bytes());
    ext.extend(sni);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend(ext);
    let mut result = vec![1, 0, 0, body.len() as u8];
    result.extend(body);
    result
}

fn server_hello() -> Vec<u8> {
    let mut b = vec![2, 0, 0, 40, 3, 3];
    b.extend([0; 32]);
    b.extend([0, 0x13, 1, 0, 0, 0]);
    b
}

fn parse(state: &mut QuicState, packet: &[u8], client: bool, time: u64) {
    assert!(state.parse(packet, client, ptr::null_mut(), Duration::from_secs(time)));
}

fn names(state: &QuicState) -> Vec<&[u8]> {
    state
        .transactions
        .iter()
        .filter_map(|tx| tx.sni.as_deref())
        .collect()
}

#[test]
fn three_interleaved_connections_reassemble_independently() {
    let mut s = QuicState::new();
    let messages = [hello("a.example"), hello("b.example"), hello("c.example")];
    for (i, message) in messages.iter().enumerate() {
        let d = [i as u8 + 1; 8];
        let c = [i as u8 + 11; 8];
        parse(
            &mut s,
            &initial(1, &d, &d, &c, 0, true, 0, &message[..20]),
            true,
            1,
        );
    }
    assert!(names(&s).is_empty());
    // A repeated tail cannot fill the gap between its first and last fragments.
    let a_tail = initial(
        1,
        &[1; 8],
        &[1; 8],
        &[11; 8],
        1,
        true,
        40,
        &messages[0][40..],
    );
    parse(&mut s, &a_tail, true, 2);
    parse(&mut s, &a_tail, true, 2);
    assert!(names(&s).is_empty());
    for (i, message) in messages.iter().enumerate().rev() {
        let d = [i as u8 + 1; 8];
        let c = [i as u8 + 11; 8];
        parse(
            &mut s,
            &initial(1, &d, &d, &c, 2, true, 20, &message[20..]),
            true,
            3,
        );
    }
    assert_eq!(
        names(&s),
        vec![b"c.example".as_slice(), b"b.example", b"a.example"]
    );
    assert_eq!(s.connections.len(), 3);
}

#[test]
fn server_cid_switch_preserves_initial_keys_and_other_connections() {
    let mut s = QuicState::new();
    let a = hello("a.example");
    let b = hello("b.example");
    parse(
        &mut s,
        &initial(1, &[1; 8], &[1; 8], &[11; 8], 0, true, 0, &a[..20]),
        true,
        1,
    );
    parse(
        &mut s,
        &initial(1, &[2; 8], &[2; 8], &[12; 8], 0, true, 0, &b[..20]),
        true,
        1,
    );
    parse(
        &mut s,
        &initial(1, &[1; 8], &[11; 8], &[21; 8], 0, false, 0, &server_hello()),
        false,
        2,
    );
    parse(
        &mut s,
        &initial(1, &[1; 8], &[21; 8], &[11; 8], 1, true, 20, &a[20..]),
        true,
        3,
    );
    assert!(s.connections[0].complete());
    assert!(!s.connections[1].complete());
    assert_eq!(
        s.encryption_flags(EncryptionHandling::ENCRYPTION_HANDLING_BYPASS),
        0
    );
    parse(
        &mut s,
        &initial(1, &[2; 8], &[2; 8], &[12; 8], 1, true, 20, &b[20..]),
        true,
        4,
    );
    assert_eq!(names(&s), vec![b"a.example".as_slice(), b"b.example"]);
}

#[test]
fn zero_length_client_ids_use_the_correct_server_initial_keys() {
    let mut s = QuicState::new();
    for i in 1..=2 {
        parse(
            &mut s,
            &initial(1, &[i; 8], &[i; 8], &[], 0, true, 0, &hello("zero.example")),
            true,
            1,
        );
    }
    for i in 1..=2 {
        parse(
            &mut s,
            &initial(1, &[i; 8], &[], &[i + 20; 8], 0, false, 0, &server_hello()),
            false,
            2,
        );
    }
    assert_eq!(s.connections.len(), 2);
    assert!(s.connections.iter().all(|c| c.complete()));
}

#[test]
fn retry_resets_only_its_connection_and_requires_integrity() {
    let mut s = QuicState::new();
    let a = hello("retry.example");
    let b = hello("other.example");
    parse(
        &mut s,
        &initial(1, &[1; 8], &[1; 8], &[11; 8], 0, true, 0, &a[..20]),
        true,
        1,
    );
    parse(
        &mut s,
        &initial(1, &[2; 8], &[2; 8], &[12; 8], 0, true, 0, &b[..20]),
        true,
        1,
    );
    let good = retry(&[11; 8], &[31; 8], &[1; 8]);
    let mut bad = good.clone();
    *bad.last_mut().unwrap() ^= 1;
    parse(&mut s, &bad, false, 2);
    // Invalid Retry must not discard the original CRYPTO prefix.
    parse(
        &mut s,
        &initial(1, &[1; 8], &[1; 8], &[11; 8], 1, true, 20, &a[20..]),
        true,
        3,
    );
    parse(&mut s, &good, false, 4);
    parse(
        &mut s,
        &initial(1, &[31; 8], &[31; 8], &[11; 8], 2, true, 0, &a),
        true,
        5,
    );
    parse(
        &mut s,
        &initial(1, &[2; 8], &[2; 8], &[12; 8], 1, true, 20, &b[20..]),
        true,
        5,
    );
    assert_eq!(s.connections.len(), 2);
    assert_eq!(
        names(&s),
        vec![
            b"retry.example".as_slice(),
            b"retry.example",
            b"other.example"
        ]
    );
}

#[test]
fn invalid_initial_and_capacity_limit_preserve_unfinished_connections() {
    let mut s = QuicState::new();
    s.max_connections = 2;
    let h = hello("bounded.example");
    for i in 1..=2 {
        parse(
            &mut s,
            &initial(1, &[i; 8], &[i; 8], &[i + 10; 8], 0, true, 0, &h[..20]),
            true,
            1,
        );
    }
    let mut invalid = initial(1, &[3; 8], &[3; 8], &[13; 8], 0, true, 0, &h);
    *invalid.last_mut().unwrap() ^= 1;
    parse(&mut s, &invalid, true, 2);
    parse(
        &mut s,
        &initial(1, &[3; 8], &[3; 8], &[13; 8], 1, true, 0, &h),
        true,
        2,
    );
    assert_eq!(s.connections.len(), 2);
    for i in 1..=2 {
        parse(
            &mut s,
            &initial(1, &[i; 8], &[i; 8], &[i + 10; 8], 1, true, 20, &h[20..]),
            true,
            3,
        );
    }
    assert_eq!(names(&s).len(), 2);
}

#[test]
fn idle_contexts_expire_without_expiring_active_connections() {
    let mut s = QuicState::new();
    s.idle_timeout = Duration::from_secs(10);
    let h = hello("expiry.example");
    parse(
        &mut s,
        &initial(1, &[1; 8], &[1; 8], &[11; 8], 0, true, 0, &h[..20]),
        true,
        1,
    );
    parse(
        &mut s,
        &initial(1, &[2; 8], &[2; 8], &[12; 8], 0, true, 0, &h[..20]),
        true,
        8,
    );
    parse(
        &mut s,
        &initial(1, &[2; 8], &[2; 8], &[12; 8], 1, true, 20, &h[20..]),
        true,
        12,
    );
    assert_eq!(s.connections.len(), 1);
    assert_eq!(s.connections[0].client_scid, [12; 8]);
    assert_eq!(names(&s), vec![b"expiry.example".as_slice()]);
}

#[test]
fn quic_v2_connections_are_independent() {
    let mut s = QuicState::new();
    let h = hello("v2.example");
    for i in 1..=2 {
        parse(
            &mut s,
            &initial(
                0x6b3343cf,
                &[i; 8],
                &[i; 8],
                &[i + 10; 8],
                0,
                true,
                0,
                &h[..20],
            ),
            true,
            1,
        );
    }
    for i in 1..=2 {
        parse(
            &mut s,
            &initial(
                0x6b3343cf,
                &[i; 8],
                &[i; 8],
                &[i + 10; 8],
                1,
                true,
                20,
                &h[20..],
            ),
            true,
            2,
        );
    }
    assert_eq!(names(&s).len(), 2);
    assert_eq!(s.connections.len(), 2);
}

// Rust-only tests pass a null parser state. End-to-end tests exercise the real C API.
#[no_mangle]
extern "C" fn SCAppLayerParserStateSetFlag(_: *mut suricata_sys::sys::AppLayerParserState, _: u16) {
    panic!("Rust tests must not call the C parser-state API");
}

#[test]
fn encrypted_cid_rotation_after_hello_does_not_create_new_transactions() {
    let mut s = QuicState::new();
    parse(
        &mut s,
        &initial(
            1,
            &[1; 8],
            &[1; 8],
            &[11; 8],
            0,
            true,
            0,
            &hello("done.example"),
        ),
        true,
        1,
    );
    parse(
        &mut s,
        &initial(1, &[1; 8], &[11; 8], &[21; 8], 0, false, 0, &server_hello()),
        false,
        2,
    );
    let count = s.transactions.len();
    let mut handshake = vec![0xe0, 0, 0, 0, 1, 8];
    handshake.extend([99; 8]);
    handshake.push(8);
    handshake.extend([11; 8]);
    handshake.push(20);
    handshake.extend([0; 20]);
    parse(&mut s, &handshake, true, 3);
    assert_eq!(s.transactions.len(), count);
    assert_eq!(
        s.encryption_flags(EncryptionHandling::ENCRYPTION_HANDLING_TRACK_ONLY),
        crate::applayer::APP_LAYER_PARSER_NO_INSPECTION_PAYLOAD
    );
    assert_eq!(
        s.encryption_flags(EncryptionHandling::ENCRYPTION_HANDLING_FULL),
        0
    );
}

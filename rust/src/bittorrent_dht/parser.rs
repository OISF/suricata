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

/*! Parses BitTorrent DHT specification BEP_0005
 *  <https://www.bittorrent.org/beps/bep_0005.html> !*/

use crate::bittorrent_dht::bittorrent_dht::BitTorrentDHTTransaction;
use bendy::decoding::{Decoder, Error, FromBencode, Object, ResultExt};

#[derive(Debug, Eq, PartialEq)]
pub struct BitTorrentDHTRequest {
    /// q = * - 20 byte string, sender's node ID in network byte order
    pub id: Vec<u8>,
    /// q = find_node - target node ID
    pub target: Option<String>,
    /// q = get_peers/announce_peer - 20-byte info hash of target torrent
    pub info_hash: Option<Vec<u8>>,
    /// q = announce_peer - token key received from previous get_peers query
    pub token: Option<String>,
    /// q = announce_peer - 0 or 1, if 1 ignore provided port and
    ///                     use source port of UDP packet
    pub implied_port: Option<u8>,
    /// q = announce_peer - port on which peer will download torrent
    pub port: Option<u16>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct BitTorrentDHTResponse {
    /// q = * - 20 byte string, receiver's node ID in network byte order
    pub id: Vec<u8>,
    /// q = find_node/get_peers - compact node info for target node or
    ///                           K(8) closest good nodes in routing table
    pub nodes: Option<Vec<u8>>,
    /// q = get_peers - list of compact peer infos
    pub values: Option<Vec<String>>,
    /// q = get_peers - token key required for sender's future
    ///                 announce_peer query
    pub token: Option<Vec<u8>>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct BitTorrentDHTError {
    /// integer representing the error code
    pub num: u16,
    /// string containing the error message
    pub msg: String,
}

impl FromBencode for BitTorrentDHTRequest {
    // Try to parse with a `max_depth` of one.
    //
    // The required max depth of a data structure is calculated as follows:
    //  - every potential nesting level encoded as bencode dictionary or
    //    list count as +1,
    //  - everything else is ignored.
    //
    // struct BitTorrentDHTRequest {   // encoded as dictionary (+1)
    //     id: String,
    //     target: Option<String>,
    //     info_hash: Option<String>,
    //     token: Option<String>,
    //     implied_port: Option<u8>,
    //     port: Option<u16>,
    // }
    const EXPECTED_RECURSION_DEPTH: usize = 1;

    fn decode_bencode_object(object: Object) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let mut id = None;
        let mut target = None;
        let mut info_hash = None;
        let mut token = None;
        let mut implied_port = None;
        let mut port = None;

        let mut dict_dec = object.try_into_dictionary()?;

        while let Some(pair) = dict_dec.next_pair()? {
            match pair {
                (b"id", value) => {
                    id = value.try_into_bytes().context("id").map(Some)?;
                }
                (b"target", value) => {
                    target = String::decode_bencode_object(value)
                        .context("target")
                        .map(Some)?;
                }
                (b"info_hash", value) => {
                    info_hash = value
                        .try_into_bytes()
                        .context("info_hash")
                        .map(|v| Some(v.to_vec()))?;
                }
                (b"token", value) => {
                    token = String::decode_bencode_object(value)
                        .context("token")
                        .map(Some)?;
                }
                (b"implied_port", value) => {
                    implied_port = u8::decode_bencode_object(value)
                        .context("implied_port")
                        .map(Some)?
                }
                (b"port", value) => {
                    port = u16::decode_bencode_object(value)
                        .context("port")
                        .map(Some)?
                }
                (_unknown_field, _) => {}
            }
        }

        let id = id.ok_or_else(|| Error::missing_field("id"))?;

        Ok(BitTorrentDHTRequest {
            id: id.to_vec(),
            target,
            info_hash,
            token,
            implied_port,
            port,
        })
    }
}

impl FromBencode for BitTorrentDHTResponse {
    // Try to parse with a `max_depth` of two.
    //
    // The required max depth of a data structure is calculated as follows:
    //  - every potential nesting level encoded as bencode dictionary or
    //    list count as +1,
    //  - everything else is ignored.
    //
    // struct BitTorrentDHTResponse {   // encoded as dictionary (+1)
    //     id: String,
    //     nodes: Option<String>,
    //     values: Option<Vec<String>>, // if present, encoded as list (+1)
    //     token: Option<String>,
    // }
    const EXPECTED_RECURSION_DEPTH: usize = 2;

    fn decode_bencode_object(object: Object) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let mut id = None;
        let mut nodes = None;
        let mut values = None;
        let mut token = None;

        let mut dict_dec = object.try_into_dictionary()?;

        while let Some(pair) = dict_dec.next_pair()? {
            match pair {
                (b"id", value) => {
                    id = value.try_into_bytes().context("id").map(Some)?;
                }
                (b"nodes", value) => {
                    nodes = value
                        .try_into_bytes()
                        .context("nodes")
                        .map(|v| Some(v.to_vec()))?;
                }
                (b"values", value) => {
                    values = Vec::decode_bencode_object(value)
                        .context("values")
                        .map(Some)?;
                }
                (b"token", value) => {
                    token = value
                        .try_into_bytes()
                        .context("token")
                        .map(|v| Some(v.to_vec()))?;
                }
                (_unknown_field, _) => {}
            }
        }

        let id = id.ok_or_else(|| Error::missing_field("id"))?;

        Ok(BitTorrentDHTResponse {
            id: id.to_vec(),
            nodes,
            values,
            token,
        })
    }
}

impl FromBencode for BitTorrentDHTError {
    // Try to parse with a `max_depth` of one.
    //
    // The required max depth of a data structure is calculated as follows:
    //  - every potential nesting level encoded as bencode dictionary or
    //    list count as +1,
    //  - everything else is ignored.
    //
    // struct BitTorrentDHTError {   // encoded as dictionary (+1)
    //     num: u16,
    //     msg: String,
    // }
    const EXPECTED_RECURSION_DEPTH: usize = 1;

    fn decode_bencode_object(object: Object) -> Result<Self, Error>
    where
        Self: Sized,
    {
        let mut num = None;
        let mut msg = None;

        let mut list_dec = object.try_into_list()?;

        while let Some(object) = list_dec.next_object()? {
            match object {
                Object::Integer(_) => {
                    num = u16::decode_bencode_object(object)
                        .context("num")
                        .map(Some)?;
                }
                Object::Bytes(_) => {
                    msg = String::decode_bencode_object(object)
                        .context("msg")
                        .map(Some)?;
                }
                _ => {}
            }
        }

        let num = num.ok_or_else(|| Error::missing_field("num"))?;
        let msg = msg.ok_or_else(|| Error::missing_field("msg"))?;

        Ok(BitTorrentDHTError { num, msg })
    }
}

pub fn parse_bittorrent_dht_packet(
    bytes: &[u8], tx: &mut BitTorrentDHTTransaction,
) -> Result<(), Error> {
    // Try to parse with a `max_depth` of three.
    //
    // The required max depth of a data structure is calculated as follows:
    //  - every potential nesting level encoded as bencode dictionary or
    //    list count as +1,
    //  - everything else is ignored.
    //
    // - Outer packet is a dictionary (+1)
    // - Max depth of child within dictionary is a BitTorrentDHTResponse (+2)
    let mut decoder = Decoder::new(bytes).with_max_depth(3);
    let object = decoder.next_object()?;

    let mut packet_type = None;
    let mut query_type = None;
    let mut query_arguments = None;
    let mut response = None;
    let mut error = None;
    let mut transaction_id = None;
    let mut client_version = None;

    let mut dict_dec = object
        .ok_or_else(|| Error::unexpected_token("Dict", "EOF"))?
        .try_into_dictionary()?;

    while let Some(pair) = dict_dec.next_pair()? {
        match pair {
            (b"y", value) => {
                // q (query) vs r (response) vs e (error)
                packet_type = String::decode_bencode_object(value)
                    .context("packet_type")
                    .map(Some)?;
            }
            (b"q", value) => {
                // query type found
                query_type = String::decode_bencode_object(value)
                    .context("query_type")
                    .map(Some)?;
            }
            (b"a", value) => {
                // query arguments found
                query_arguments = BitTorrentDHTRequest::decode_bencode_object(value)
                    .context("query_arguments")
                    .map(Some)?;
            }
            (b"r", value) => {
                // response found
                response = BitTorrentDHTResponse::decode_bencode_object(value)
                    .context("response")
                    .map(Some)?;
            }
            (b"e", value) => {
                // error found
                error = BitTorrentDHTError::decode_bencode_object(value)
                    .context("error")
                    .map(Some)?;
            }
            (b"t", value) => {
                // transaction id found
                transaction_id = value.try_into_bytes().context("transaction_id").map(Some)?;
            }
            (b"v", value) => {
                // client version string found
                client_version = value
                    .try_into_bytes()
                    .context("client_version")
                    .map(|v| Some(v.to_vec()))?;
            }
            (_unknown_field, _) => {}
        }
    }

    if let Some(t) = packet_type {
        match t.as_str() {
            "q" => {
                tx.request_type =
                    Some(query_type.ok_or_else(|| Error::missing_field("query_type"))?);
                tx.request =
                    Some(query_arguments.ok_or_else(|| Error::missing_field("query_arguments"))?);
            }
            "r" => {
                tx.response = Some(response.ok_or_else(|| Error::missing_field("response"))?);
            }
            "e" => {
                tx.error = Some(error.ok_or_else(|| Error::missing_field("error"))?);
            }
            v => {
                return Err(Error::unexpected_token("packet_type q, r, or e", v));
            }
        }
    } else {
        return Err(Error::missing_field("packet_type"));
    }

    tx.transaction_id = transaction_id
        .ok_or_else(|| Error::missing_field("transaction_id"))?
        .to_vec();
    // Client version string is an optional field
    tx.client_version = client_version;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[test_case(
        b"d2:id20:abcdefghij012345678912:implied_porti1e9:info_hash20:mnopqrstuvwxyz1234564:porti6881e5:token8:aoeusnthe",
        BitTorrentDHTRequest { id: b"abcdefghij0123456789".to_vec(), implied_port: Some(1u8), info_hash: Some(b"mnopqrstuvwxyz123456".to_vec()), port: Some(6881u16), token: Some("aoeusnth".to_string()), target: None } ;
        "test request from bencode 1")]
    #[test_case(
        b"d2:id20:abcdefghij0123456789e",
        BitTorrentDHTRequest { id: b"abcdefghij0123456789".to_vec(), implied_port: None, info_hash: None, port: None, token: None, target: None } ;
        "test request from bencode 2")]
    #[test_case(
        b"d2:id20:abcdefghij01234567896:target20:mnopqrstuvwxyz123456e",
        BitTorrentDHTRequest { id: b"abcdefghij0123456789".to_vec(), implied_port: None, info_hash: None, port: None, token: None, target: Some("mnopqrstuvwxyz123456".to_string()) } ;
        "test request from bencode 3")]
    #[test_case(
        b"d2:id20:abcdefghij01234567899:info_hash20:mnopqrstuvwxyz123456e",
        BitTorrentDHTRequest { id: b"abcdefghij0123456789".to_vec(), implied_port: None, info_hash: Some(b"mnopqrstuvwxyz123456".to_vec()), port: None, token: None, target: None } ;
        "test request from bencode 4")]
    fn test_request_from_bencode(encoded: &[u8], expected: BitTorrentDHTRequest) {
        let decoded = BitTorrentDHTRequest::from_bencode(encoded).unwrap();
        assert_eq!(expected, decoded);
    }

    #[test_case(
        b"d12:implied_porti1e9:info_hash20:mnopqrstuvwxyz1234564:porti6881e5:token8:aoeusnthe",
        "Error: missing field: id" ;
        "test request from bencode err 1")]
    #[test_case(
        b"d2:id20:abcdefghij012345678912:implied_porti9999e9:info_hash20:mnopqrstuvwxyz1234564:porti6881e5:token8:aoeusnthe",
        "Error: malformed content discovered in implied_port" ;
        "test request from bencode err 2")]
    #[test_case(
        b"d2:id20:abcdefghij012345678912:implied_porti-1e9:info_hash20:mnopqrstuvwxyz1234564:porti6881e5:token8:aoeusnthe",
        "Error: malformed content discovered in implied_port" ;
        "test request from bencode err 3")]
    #[test_case(
        b"d2:id20:abcdefghij012345678912:implied_porti1e9:info_hash20:mnopqrstuvwxyz1234564:porti9999999e5:token8:aoeusnthe",
        "Error: malformed content discovered in port" ;
        "test request from bencode err 4")]
    #[test_case(
        b"d2:id20:abcdefghij012345678912:implied_porti1e9:info_hash20:mnopqrstuvwxyz1234564:porti-1e5:token8:aoeusnthe",
        "Error: malformed content discovered in port" ;
        "test request from bencode err 5")]
    #[test_case(
        b"i123e",
        "Error: discovered Dict but expected Num" ;
        "test request from bencode err 6")]
    fn test_request_from_bencode_err(encoded: &[u8], expected_error: &str) {
        let err = BitTorrentDHTRequest::from_bencode(encoded).unwrap_err();
        assert_eq!(expected_error, err.to_string());
    }

    #[test_case(
        b"d2:id20:abcdefghij01234567895:token8:aoeusnth6:valueslee",
        BitTorrentDHTResponse { id: b"abcdefghij0123456789".to_vec(), token: Some(b"aoeusnth".to_vec()), values: Some(vec![]), nodes: None } ;
        "test response from bencode 1")]
    #[test_case(
        b"d2:id20:abcdefghij01234567895:token8:aoeusnth6:valuesl6:axje.uee",
        BitTorrentDHTResponse { id: b"abcdefghij0123456789".to_vec(), token: Some(b"aoeusnth".to_vec()), values: Some(vec!["axje.u".to_string()]), nodes: None } ;
        "test response from bencode 2")]
    #[test_case(
        b"d2:id20:abcdefghij01234567895:token8:aoeusnth6:valuesl6:axje.u6:idhtnmee",
        BitTorrentDHTResponse { id: b"abcdefghij0123456789".to_vec(), token: Some(b"aoeusnth".to_vec()), values: Some(vec!["axje.u".to_string(), "idhtnm".to_string()]), nodes: None } ;
        "test response from bencode 3")]
    #[test_case(
        b"d2:id20:mnopqrstuvwxyz123456e",
        BitTorrentDHTResponse { id: b"mnopqrstuvwxyz123456".to_vec(), token: None, values: None, nodes: None } ;
        "test response from bencode 4")]
    #[test_case(
        b"d2:id20:0123456789abcdefghij5:nodes9:def456...e",
        BitTorrentDHTResponse { id: b"0123456789abcdefghij".to_vec(), token: None, values: None, nodes: Some(b"def456...".to_vec()) } ;
        "test response from bencode 5")]
    #[test_case(
        b"d2:id20:abcdefghij01234567895:nodes9:def456...5:token8:aoeusnthe",
        BitTorrentDHTResponse { id: b"abcdefghij0123456789".to_vec(), token: Some(b"aoeusnth".to_vec()), values: None, nodes: Some(b"def456...".to_vec()) } ;
        "test response from bencode 6")]
    fn test_response_from_bencode(encoded: &[u8], expected: BitTorrentDHTResponse) {
        let decoded = BitTorrentDHTResponse::from_bencode(encoded).unwrap();
        assert_eq!(expected, decoded);
    }

    #[test_case(
        b"d5:token8:aoeusnth6:valuesl6:axje.u6:idhtnmee",
        "Error: missing field: id" ;
        "test response from bencode err 1")]
    #[test_case(
        b"i123e",
        "Error: discovered Dict but expected Num" ;
        "test response from bencode err 2")]
    fn test_response_from_bencode_err(encoded: &[u8], expected_error: &str) {
        let err = BitTorrentDHTResponse::from_bencode(encoded).unwrap_err();
        assert_eq!(expected_error, err.to_string());
    }

    #[test_case(
        b"li201e23:A Generic Error Ocurrede",
        BitTorrentDHTError { num: 201u16, msg: "A Generic Error Ocurred".to_string() } ;
        "test error from bencode 1")]
    #[test_case(
        b"li202e12:Server Errore",
        BitTorrentDHTError { num: 202u16, msg: "Server Error".to_string() } ;
        "test error from bencode 2")]
    #[test_case(
        b"li203e14:Protocol Errore",
        BitTorrentDHTError { num: 203u16, msg: "Protocol Error".to_string() } ;
        "test error from bencode 3")]
    #[test_case(
        b"li204e14:Method Unknowne",
        BitTorrentDHTError { num: 204u16, msg: "Method Unknown".to_string() } ;
        "test error from bencode 4")]
    fn test_error_from_bencode(encoded: &[u8], expected: BitTorrentDHTError) {
        let decoded = BitTorrentDHTError::from_bencode(encoded).unwrap();
        assert_eq!(expected, decoded);
    }

    #[test_case(
        b"l23:A Generic Error Ocurrede",
        "Error: missing field: num" ;
        "test error from bencode err 1")]
    #[test_case(
        b"li201ee",
        "Error: missing field: msg" ;
        "test error from bencode err 2")]
    #[test_case(
        b"li999999ee",
        "Error: malformed content discovered in num" ;
        "test error from bencode err 3")]
    #[test_case(
        b"li-1ee",
        "Error: malformed content discovered in num" ;
        "test error from bencode err 4")]
    #[test_case(
        b"i123e",
        "Error: discovered List but expected Num" ;
        "test error from bencode err 5")]
    fn test_error_from_bencode_err(encoded: &[u8], expected_error: &str) {
        let err = BitTorrentDHTError::from_bencode(encoded).unwrap_err();
        assert_eq!(expected_error, err.to_string());
    }

    #[test_case(
        b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:v4:UT011:y1:qe",
        Some("ping".to_string()),
        Some(BitTorrentDHTRequest { id: b"abcdefghij0123456789".to_vec(), implied_port: None, info_hash: None, port: None, token: None, target: None }),
        None,
        None,
        b"aa".to_vec(),
        Some(b"UT01".to_vec()) ;
        "test parse bittorrent dht packet 1"
    )]
    #[test_case(
        b"d1:rd2:id20:abcdefghij01234567895:token8:aoeusnth6:valuesl6:axje.u6:idhtnmee1:t2:aa1:y1:re",
        None,
        None,
        Some(BitTorrentDHTResponse { id: b"abcdefghij0123456789".to_vec(), token: Some(b"aoeusnth".to_vec()), values: Some(vec!["axje.u".to_string(), "idhtnm".to_string()]), nodes: None}),
        None,
        b"aa".to_vec(),
        None ;
        "test parse bittorrent dht packet 2"
    )]
    #[test_case(
        b"d1:eli201e23:A Generic Error Ocurrede1:t2:aa1:v4:UT011:y1:ee",
        None,
        None,
        None,
        Some(BitTorrentDHTError { num: 201u16, msg: "A Generic Error Ocurred".to_string() }),
        b"aa".to_vec(),
        Some(b"UT01".to_vec()) ;
        "test parse bittorrent dht packet 3"
    )]
    fn test_parse_bittorrent_dht_packet(
        encoded: &[u8], request_type: Option<String>,
        expected_request: Option<BitTorrentDHTRequest>,
        expected_response: Option<BitTorrentDHTResponse>,
        expected_error: Option<BitTorrentDHTError>, expected_transaction_id: Vec<u8>,
        expected_client_version: Option<Vec<u8>>,
    ) {
        let mut tx = BitTorrentDHTTransaction::new();
        parse_bittorrent_dht_packet(encoded, &mut tx).unwrap();
        assert_eq!(request_type, tx.request_type);
        assert_eq!(expected_request, tx.request);
        assert_eq!(expected_response, tx.response);
        assert_eq!(expected_error, tx.error);
        assert_eq!(expected_transaction_id, tx.transaction_id);
        assert_eq!(expected_client_version, tx.client_version);
    }

    #[test_case(
        b"",
        "Error: discovered Dict but expected EOF" ;
        "test parse bittorrent dht packet err 1"
    )]
    #[test_case(
        b"li2123ei321ee",
        "Error: discovered Dict but expected List" ;
        "test parse bittorrent dht packet err 2"
    )]
    #[test_case(
        b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aae",
        "Error: missing field: packet_type" ;
        "test parse bittorrent dht packet err 3"
    )]
    #[test_case(
        b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:t2:aa1:y1:Fe",
        "Error: discovered packet_type q, r, or e but expected F" ;
        "test parse bittorrent dht packet err 4"
    )]
    #[test_case(
        b"d1:ad2:id20:abcdefghij0123456789e1:t2:aa1:y1:qe",
        "Error: missing field: query_type" ;
        "test parse bittorrent dht packet err 5"
    )]
    #[test_case(
        b"d1:q4:ping1:t2:aa1:y1:qe",
        "Error: missing field: query_arguments" ;
        "test parse bittorrent dht packet err 6"
    )]
    #[test_case(
        b"d1:t2:aa1:y1:re",
        "Error: missing field: response" ;
        "test parse bittorrent dht packet err 7"
    )]
    #[test_case(
        b"d1:t2:aa1:y1:ee",
        "Error: missing field: error" ;
        "test parse bittorrent dht packet err 8"
    )]
    #[test_case(
        b"d1:ade1:q4:ping1:t2:aa1:y1:qe",
        "Error: missing field: id in query_arguments" ;
        "test parse bittorrent dht packet err 9"
    )]
    #[test_case(
        b"d1:ad2:id20:abcdefghij0123456789e1:q4:ping1:y1:qe",
        "Error: missing field: transaction_id" ;
        "test parse bittorrent dht packet err 10"
    )]
    fn test_parse_bittorrent_dht_packet_err(encoded: &[u8], expected_error: &str) {
        let mut tx = BitTorrentDHTTransaction::new();
        let err = parse_bittorrent_dht_packet(encoded, &mut tx).unwrap_err();
        assert_eq!(expected_error, err.to_string());
    }
}

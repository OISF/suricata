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

use crate::krb::krb5::{test_weak_encryption, KRB5Transaction};

use kerberos_parser::krb5::EncryptionType;

use nom7::branch::alt;
use nom7::bytes::complete::{is_a, tag, take_while, take_while1};
use nom7::character::complete::char;
use nom7::combinator::{all_consuming, map_res, opt};
use nom7::multi::many1;
use nom7::IResult;

use std::ffi::CStr;

#[no_mangle]
pub unsafe extern "C" fn rs_krb5_tx_get_msgtype(tx: &mut KRB5Transaction, ptr: *mut u32) {
    *ptr = tx.msg_type.0;
}

/// Get error code, if present in transaction
/// Return 0 if error code was filled, else 1
#[no_mangle]
pub unsafe extern "C" fn rs_krb5_tx_get_errcode(tx: &mut KRB5Transaction, ptr: *mut i32) -> u32 {
    match tx.error_code {
        Some(ref e) => {
            *ptr = e.0;
            0
        }
        None => 1,
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_krb5_tx_get_cname(
    tx: &mut KRB5Transaction, i: u32, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    if let Some(ref s) = tx.cname {
        if (i as usize) < s.name_string.len() {
            let value = &s.name_string[i as usize];
            *buffer = value.as_ptr();
            *buffer_len = value.len() as u32;
            return 1;
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn rs_krb5_tx_get_sname(
    tx: &mut KRB5Transaction, i: u32, buffer: *mut *const u8, buffer_len: *mut u32,
) -> u8 {
    if let Some(ref s) = tx.sname {
        if (i as usize) < s.name_string.len() {
            let value = &s.name_string[i as usize];
            *buffer = value.as_ptr();
            *buffer_len = value.len() as u32;
            return 1;
        }
    }
    0
}

const KRB_TICKET_FASTARRAY_SIZE: usize = 256;

#[derive(Debug)]
pub struct DetectKrb5TicketEncryptionList {
    positive: [bool; KRB_TICKET_FASTARRAY_SIZE],
    negative: [bool; KRB_TICKET_FASTARRAY_SIZE],
    other: Vec<EncryptionType>,
}

impl DetectKrb5TicketEncryptionList {
    pub fn new() -> DetectKrb5TicketEncryptionList {
        DetectKrb5TicketEncryptionList {
            positive: [false; KRB_TICKET_FASTARRAY_SIZE],
            negative: [false; KRB_TICKET_FASTARRAY_SIZE],
            other: Vec::new(),
        }
    }
}

#[derive(Debug)]
pub enum DetectKrb5TicketEncryptionData {
    WEAK(bool),
    LIST(DetectKrb5TicketEncryptionList),
}

pub fn detect_parse_encryption_weak(i: &str) -> IResult<&str, DetectKrb5TicketEncryptionData> {
    let (i, neg) = opt(char('!'))(i)?;
    let (i, _) = tag("weak")(i)?;
    let value = match neg {
        Some(_) => false,
        _ => true,
    };
    return Ok((i, DetectKrb5TicketEncryptionData::WEAK(value)));
}

trait MyFromStr {
    fn from_str(s: &str) -> Result<Self, String>
    where
        Self: Sized;
}

impl MyFromStr for EncryptionType {
    fn from_str(s: &str) -> Result<Self, String> {
        let su_slice: &str = &*s;
        match su_slice {
            "des-cbc-crc" => Ok(EncryptionType::DES_CBC_CRC),
            "des-cbc-md4" => Ok(EncryptionType::DES_CBC_MD4),
            "des-cbc-md5" => Ok(EncryptionType::DES_CBC_MD5),
            "des3-cbc-md5" => Ok(EncryptionType::DES3_CBC_MD5),
            "des3-cbc-sha1" => Ok(EncryptionType::DES3_CBC_SHA1),
            "dsaWithSHA1-CmsOID" => Ok(EncryptionType::DSAWITHSHA1_CMSOID),
            "md5WithRSAEncryption-CmsOID" => Ok(EncryptionType::MD5WITHRSAENCRYPTION_CMSOID),
            "sha1WithRSAEncryption-CmsOID" => Ok(EncryptionType::SHA1WITHRSAENCRYPTION_CMSOID),
            "rc2CBC-EnvOID" => Ok(EncryptionType::RC2CBC_ENVOID),
            "rsaEncryption-EnvOID" => Ok(EncryptionType::RSAENCRYPTION_ENVOID),
            "rsaES-OAEP-ENV-OID" => Ok(EncryptionType::RSAES_OAEP_ENV_OID),
            "des-ede3-cbc-Env-OID" => Ok(EncryptionType::DES_EDE3_CBC_ENV_OID),
            "des3-cbc-sha1-kd" => Ok(EncryptionType::DES3_CBC_SHA1_KD),
            "aes128-cts-hmac-sha1-96" => Ok(EncryptionType::AES128_CTS_HMAC_SHA1_96),
            "aes256-cts-hmac-sha1-96" => Ok(EncryptionType::AES256_CTS_HMAC_SHA1_96),
            "aes128-cts-hmac-sha256-128" => Ok(EncryptionType::AES128_CTS_HMAC_SHA256_128),
            "aes256-cts-hmac-sha384-192" => Ok(EncryptionType::AES256_CTS_HMAC_SHA384_192),
            "rc4-hmac" => Ok(EncryptionType::RC4_HMAC),
            "rc4-hmac-exp" => Ok(EncryptionType::RC4_HMAC_EXP),
            "camellia128-cts-cmac" => Ok(EncryptionType::CAMELLIA128_CTS_CMAC),
            "camellia256-cts-cmac" => Ok(EncryptionType::CAMELLIA256_CTS_CMAC),
            "subkey-keymaterial" => Ok(EncryptionType::SUBKEY_KEYMATERIAL),
            "rc4-md4" => Ok(EncryptionType::RC4_MD4),
            "rc4-plain2" => Ok(EncryptionType::RC4_PLAIN2),
            "rc4-lm" => Ok(EncryptionType::RC4_LM),
            "rc4-sha" => Ok(EncryptionType::RC4_SHA),
            "des-plain" => Ok(EncryptionType::DES_PLAIN),
            "rc4-hmac-OLD" => Ok(EncryptionType::RC4_HMAC_OLD),
            "rc4-plain-OLD" => Ok(EncryptionType::RC4_PLAIN_OLD),
            "rc4-hmac-OLD-exp" => Ok(EncryptionType::RC4_HMAC_OLD_EXP),
            "rc4-plain-OLD-exp" => Ok(EncryptionType::RC4_PLAIN_OLD_EXP),
            "rc4-plain" => Ok(EncryptionType::RC4_PLAIN),
            "rc4-plain-exp" => Ok(EncryptionType::RC4_PLAIN_EXP),
            _ => {
                if let Ok(num) = s.parse::<i32>() {
                    return Ok(EncryptionType(num));
                } else {
                    return Err(format!("'{}' is not a valid value for EncryptionType", s));
                }
            }
        }
    }
}

pub fn is_alphanumeric_or_dash(chr: char) -> bool {
    return chr.is_alphanumeric() || chr == '-';
}

pub fn detect_parse_encryption_item(i: &str) -> IResult<&str, EncryptionType> {
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, e) = map_res(take_while1(is_alphanumeric_or_dash), |s: &str| {
        EncryptionType::from_str(s)
    })(i)?;
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, _) = opt(char(','))(i)?;
    return Ok((i, e));
}

pub fn detect_parse_encryption_list(i: &str) -> IResult<&str, DetectKrb5TicketEncryptionData> {
    let mut l = DetectKrb5TicketEncryptionList::new();
    let (i, v) = many1(detect_parse_encryption_item)(i)?;
    for &val in v.iter() {
        let vali = val.0;
        if vali < 0 && ((-vali) as usize) < KRB_TICKET_FASTARRAY_SIZE {
            l.negative[(-vali) as usize] = true;
        } else if vali >= 0 && (vali as usize) < KRB_TICKET_FASTARRAY_SIZE {
            l.positive[vali as usize] = true;
        } else {
            l.other.push(val);
        }
    }
    return Ok((i, DetectKrb5TicketEncryptionData::LIST(l)));
}

pub fn detect_parse_encryption(i: &str) -> IResult<&str, DetectKrb5TicketEncryptionData> {
    let (i, _) = opt(is_a(" "))(i)?;
    let (i, parsed) = alt((detect_parse_encryption_weak, detect_parse_encryption_list))(i)?;
    let (i, _) = all_consuming(take_while(|c| c == ' '))(i)?;
    return Ok((i, parsed));
}

#[no_mangle]
pub unsafe extern "C" fn rs_krb5_detect_encryption_parse(
    ustr: *const std::os::raw::c_char,
) -> *mut DetectKrb5TicketEncryptionData {
    let ft_name: &CStr = CStr::from_ptr(ustr); //unsafe
    if let Ok(s) = ft_name.to_str() {
        if let Ok((_, ctx)) = detect_parse_encryption(s) {
            let boxed = Box::new(ctx);
            return Box::into_raw(boxed) as *mut _;
        }
    }
    return std::ptr::null_mut();
}

#[no_mangle]
pub unsafe extern "C" fn rs_krb5_detect_encryption_match(
    tx: &mut KRB5Transaction, ctx: &DetectKrb5TicketEncryptionData,
) -> std::os::raw::c_int {
    if let Some(x) = tx.ticket_etype {
        match ctx {
            DetectKrb5TicketEncryptionData::WEAK(w) => {
                if (test_weak_encryption(x) && *w) || (!test_weak_encryption(x) && !*w) {
                    return 1;
                }
            }
            DetectKrb5TicketEncryptionData::LIST(l) => {
                let vali = x.0;
                if vali < 0 && ((-vali) as usize) < KRB_TICKET_FASTARRAY_SIZE {
                    if l.negative[(-vali) as usize] {
                        return 1;
                    }
                } else if vali >= 0 && (vali as usize) < KRB_TICKET_FASTARRAY_SIZE {
                    if l.positive[vali as usize] {
                        return 1;
                    }
                } else {
                    for &val in l.other.iter() {
                        if x == val {
                            return 1;
                        }
                    }
                }
            }
        }
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_krb5_detect_encryption_free(ctx: &mut DetectKrb5TicketEncryptionData) {
    // Just unbox...
    std::mem::drop(Box::from_raw(ctx));
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_detect_parse_encryption() {
        match detect_parse_encryption(" weak  ") {
            Ok((rem, ctx)) => {
                match ctx {
                    DetectKrb5TicketEncryptionData::WEAK(w) => {
                        assert_eq!(w, true);
                    }
                    _ => {
                        panic!("Result should have been weak.");
                    }
                }
                // And we should have no bytes left.
                assert_eq!(rem.len(), 0);
            }
            _ => {
                panic!("Result should have been ok.");
            }
        }
        match detect_parse_encryption("!weak") {
            Ok((rem, ctx)) => {
                match ctx {
                    DetectKrb5TicketEncryptionData::WEAK(w) => {
                        assert_eq!(w, false);
                    }
                    _ => {
                        panic!("Result should have been weak.");
                    }
                }
                // And we should have no bytes left.
                assert_eq!(rem.len(), 0);
            }
            _ => {
                panic!("Result should have been ok.");
            }
        }
        match detect_parse_encryption(" des-cbc-crc , -128,2 257") {
            Ok((rem, ctx)) => {
                match ctx {
                    DetectKrb5TicketEncryptionData::LIST(l) => {
                        assert_eq!(l.positive[EncryptionType::DES_CBC_CRC.0 as usize], true);
                        assert_eq!(l.negative[128], true);
                        assert_eq!(l.positive[2], true);
                        assert_eq!(l.other.len(), 1);
                        assert_eq!(l.other[0], EncryptionType(257));
                    }
                    _ => {
                        panic!("Result should have been list.");
                    }
                }
                // And we should have no bytes left.
                assert_eq!(rem.len(), 0);
            }
            _ => {
                panic!("Result should have been ok.");
            }
        }
    }
}

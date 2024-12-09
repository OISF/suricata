use flate2::bufread::ZlibDecoder;
use nom7::bytes::streaming::take as takes;
use nom7::combinator::verify;
use nom7::number::streaming::{le_u32, le_u64, le_u8};
use nom7::IResult;
use std::io::Read;

#[derive(Clone, Debug, Default)]
pub struct ZabbixPdu {
    pub flags: u8,
    pub data: Vec<u8>,
    pub wrong_decompressed_len: bool,
    pub error_decompression: bool,
    pub rem_len: u64,
}

pub fn check_zabbix(i: &[u8]) -> bool {
    let r = verify(le_u32::<&[u8], nom7::error::Error<&[u8]>>, |&v| {
        v == 0x4458425a
    })(i);
    r.is_ok()
}

pub fn parse_zabbix(i: &[u8]) -> IResult<&[u8], ZabbixPdu> {
    let (i, _magic) = le_u32(i)?;
    let (i, flags) = le_u8(i)?;
    let large = (flags & 4) != 0;
    let (i, (pdu_len, decompressed_len)) = if large {
        let (i2, pdu_len) = le_u64(i)?;
        let (i2, decompressed_len) = le_u64(i2)?;
        Ok((i2, (pdu_len, decompressed_len)))
    } else {
        let (i2, pdu_len) = le_u32(i)?;
        let (i2, decompressed_len) = le_u32(i2)?;
        Ok((i2, (pdu_len as u64, decompressed_len as u64)))
    }?;
    let mut wrong_decompressed_len = false;
    let mut error_decompression = false;
    //TODO make configurable
    let take_len = std::cmp::min(pdu_len, 4096);
    let (i, data) = takes(pdu_len as usize)(i)?;
    let rem_len = take_len - pdu_len;
    let data = if (flags & 2) != 0 {
        let mut z = ZlibDecoder::new(data);
        let mut dec_data = Vec::new();
        if let Ok(n) = z.read_to_end(&mut dec_data) {
            if n as u64 != decompressed_len {
                wrong_decompressed_len = true;
            }
            dec_data
        } else {
            error_decompression = true;
            data.to_vec()
        }
    } else {
        data.to_vec()
    };
    Ok((
        i,
        ZabbixPdu {
            flags,
            data,
            wrong_decompressed_len,
            error_decompression,
            rem_len,
        },
    ))
}

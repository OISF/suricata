/* Copyright (C) 2024 Open Information Security Foundation
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

// Author: QianKaiLin <linqiankai666@outlook.com>

//! MySQL nom parsers

use nom7::{
    bytes::streaming::{take, take_till},
    combinator::{cond, map, verify},
    multi::{many_m_n, many_till},
    number::streaming::{
        be_i8, be_u32, be_u8, le_f32, le_f64, le_i16, le_i32, le_i64, le_u16, le_u24, le_u32,
        le_u64,
    },
    IResult,
};
use num::{FromPrimitive, ToPrimitive};
use suricata_derive::EnumStringU8;

#[allow(dead_code)]
pub const CLIENT_LONG_PASSWORD: u32 = BIT_U32!(0);
#[allow(dead_code)]
pub const CLIENT_FOUND_ROWS: u32 = BIT_U32!(1);
#[allow(dead_code)]
pub const CLIENT_LONG_FLAG: u32 = BIT_U32!(2);
const CLIENT_CONNECT_WITH_DB: u32 = BIT_U32!(3);
#[allow(dead_code)]
const CLIENT_NO_SCHEMA: u32 = BIT_U32!(4);
#[allow(dead_code)]
const CLIENT_COMPRESS: u32 = BIT_U32!(5);
#[allow(dead_code)]
const CLIENT_ODBC: u32 = BIT_U32!(6);
#[allow(dead_code)]
const CLIENT_LOCAL_FILES: u32 = BIT_U32!(7);
#[allow(dead_code)]
const CLIENT_IGNORE_SPACE: u32 = BIT_U32!(8);
const CLIENT_PROTOCOL_41: u32 = BIT_U32!(9);
#[allow(dead_code)]
const CLIENT_INTERACTIVE: u32 = BIT_U32!(10);
pub const CLIENT_SSL: u32 = BIT_U32!(11);
#[allow(dead_code)]
pub const CLIENT_IGNORE_SIGPIPE: u32 = BIT_U32!(12);
#[allow(dead_code)]
pub const CLIENT_TRANSACTIONS: u32 = BIT_U32!(13);
#[allow(dead_code)]
pub const CLIENT_RESERVED: u32 = BIT_U32!(14);
#[allow(dead_code)]
pub const CLIENT_RESERVED2: u32 = BIT_U32!(15);
#[allow(dead_code)]
pub const CLIENT_MULTI_STATEMENTS: u32 = BIT_U32!(16);
#[allow(dead_code)]
pub const CLIENT_MULTI_RESULTS: u32 = BIT_U32!(17);
#[allow(dead_code)]
pub const CLIENT_PS_MULTI_RESULTS: u32 = BIT_U32!(18);
#[allow(dead_code)]
pub const CLIENT_PLUGIN_AUTH: u32 = BIT_U32!(19);
#[allow(dead_code)]
pub const CLIENT_CONNECT_ATTRS: u32 = BIT_U32!(20);
#[allow(dead_code)]
pub const CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: u32 = BIT_U32!(21);
#[allow(dead_code)]
pub const CLIENT_CAN_HANDLE_EXPIRED_PASSWORDS: u32 = BIT_U32!(22);
#[allow(dead_code)]
pub const CLIENT_SESSION_TRACK: u32 = BIT_U32!(23);
pub const CLIENT_DEPRECATE_EOF: u32 = BIT_U32!(24);
#[allow(dead_code)]
pub const CLIENT_OPTIONAL_RESULTSET_METADATA: u32 = BIT_U32!(25);
#[allow(dead_code)]
pub const CLIENT_ZSTD_COMPRESSION_ALGORITHM: u32 = BIT_U32!(26);
#[allow(dead_code)]
pub const CLIENT_QUERY_ATTRIBUTES: u32 = BIT_U32!(27);
#[allow(dead_code)]
pub const MULTI_FACTOR_AUTHENTICATION: u32 = BIT_U32!(28);
#[allow(dead_code)]
pub const CLIENT_CAPABILITY_EXTENSION: u32 = BIT_U32!(29);
#[allow(dead_code)]
pub const CLIENT_SSL_VERIFY_SERVER_CERT: u32 = BIT_U32!(30);
#[allow(dead_code)]
pub const CLIENT_REMEMBER_OPTIONS: u32 = BIT_U32!(31);

#[allow(dead_code)]
pub const FIELD_FLAGS_UNSIGNED: u32 = BIT_U32!(5);

const PAYLOAD_MAX_LEN: u32 = 0xffffff;

#[repr(u8)]
#[derive(Debug, Clone, Copy, EnumStringU8, FromPrimitive)]
pub enum FieldType {
    Decimal = 0,
    Tiny = 1,
    Short = 2,
    Long = 3,
    Float = 4,
    Double = 5,
    NULL = 6,
    Timestamp = 7,
    LongLong = 8,
    Int24 = 9,
    Date = 10,
    Time = 11,
    Datetime = 12,
    Year = 13,
    NewDate = 14,
    Varchar = 15,
    Bit = 16,
    Timestamp2 = 17,
    Datetime2 = 18,
    Time2 = 19,
    Array = 20,
    Unknown = 241,
    Vector = 242,
    Invalid = 243,
    Bool = 244,
    Json = 245,
    NewDecimal = 246,
    Enum = 247,
    Set = 248,
    TinyBlob = 249,
    MediumBlob = 250,
    LongBlob = 251,
    Blob = 252,
    VarString = 253,
    String = 254,
    Geometry = 255,
}

#[inline]
fn parse_field_type(field_type: u8) -> FieldType {
    if let Some(f) = FromPrimitive::from_u8(field_type) {
        f
    } else {
        FieldType::Invalid
    }
}

#[derive(Debug)]
pub struct MysqlPacket<'a> {
    pub pkt_len: usize,
    pub pkt_num: u8,

    payload: &'a mut [u8],
}

impl<'a> Drop for MysqlPacket<'a> {
    fn drop(&mut self) {
        unsafe {
            std::mem::drop(Box::from_raw(self.payload as *mut [u8]));
        }
    }
}

#[derive(Debug)]
pub struct MysqlEofPacket {
    pub warnings: u16,
    pub status_flags: u16,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct StmtLongData {
    pub statement_id: u32,
    pub param_id: u16,
    pub payload: String,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MysqlCommand {
    Unknown,
    Quit,
    Ping,
    Statistics,
    Debug,
    ChangeUser,
    ResetConnection,
    SetOption,
    InitDb {
        schema: String,
    },
    Query {
        query: String,
    },
    FieldList {
        table: String,
    },
    StmtPrepare {
        query: String,
    },
    StmtSendLongData(StmtLongData),
    StmtExecute {
        statement_id: u32,
        params: Option<Vec<String>>,
    },
    StmtFetch {
        statement_id: u32,
        number_rows: u32,
    },
    StmtReset {
        statement_id: u32,
    },
    StmtClose {
        statement_id: u32,
    },
}

impl std::fmt::Display for MysqlCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            MysqlCommand::Quit => write!(f, "quit"),
            MysqlCommand::Query { query } => write!(f, "{}", query),
            MysqlCommand::Ping => write!(f, "ping"),
            _ => write!(f, ""),
        }
    }
}

#[derive(Debug, Clone)]
pub struct MysqlColumnDefinition {
    pub catalog: String,
    pub schema: String,
    pub table: String,
    pub orig_table: String,
    pub name: String,
    pub character_set: u16,
    pub column_length: u32,
    pub field_type: FieldType,
    pub flags: u16,
    pub decimals: u8,
}

#[derive(Debug)]
pub struct MysqlResultSetRow {
    pub texts: Vec<String>,
}

#[derive(Debug)]
pub enum MysqlResultBinarySetRow {
    Err,
    Text(String),
}

#[derive(Debug)]
pub struct MysqlHandshakeRequest {
    // pub header: MysqlPacket,
    pub protocol: u8,
    pub version: String,
    pub conn_id: u32,
    pub salt1: String,
    pub capability_flags1: u16,
    pub character_set: u8,
    pub status_flags: u16,
    pub capability_flags2: u16,
    pub auth_plugin_len: u8,
    pub salt2: String,
    pub auth_plugin_data: Option<String>,
}

#[derive(Debug)]
pub struct MysqlHandshakeResponseAttribute {
    pub key: String,
    pub value: String,
}

#[derive(Debug)]
pub struct MysqlSSLRequest {
    pub filter: Option<String>,
}

#[derive(Debug)]
pub struct MysqlHandshakeResponse {
    pub username: String,
    pub auth_response_len: u8,
    pub auth_response: String,
    pub database: Option<String>,
    pub client_flags: u32,
    pub client_plugin_name: Option<String>,
    pub attributes: Option<Vec<MysqlHandshakeResponseAttribute>>,
    pub zstd_compression_level: Option<u8>,
}

#[derive(Debug)]
pub struct MysqlAuthSwtichRequest {
    pub plugin_name: String,
    pub plugin_data: String,
}

#[derive(Debug)]
pub struct MysqlRequest {
    // pub header: MysqlPacket,
    pub command_code: u8,
    pub command: MysqlCommand,
}

#[derive(Debug)]
pub enum MysqlResponsePacket {
    Unknown,
    AuthMoreData {
        data: u8,
    },
    LocalInFileRequest,
    AuthData,
    Statistics,
    AuthSwithRequest,
    EOF,
    Ok {
        rows: u64,
        flags: u16,
        warnings: u16,
    },
    Err {
        error_code: u16,
        error_message: String,
    },
    FieldsList {
        columns: Option<Vec<MysqlColumnDefinition>>,
    },
    ResultSet {
        n_cols: u64,
        columns: Vec<MysqlColumnDefinition>,
        eof: MysqlEofPacket,
        rows: Vec<MysqlResultSetRow>,
    },
    BinaryResultSet {
        n_cols: u64,
        eof: MysqlEofPacket,
        rows: Vec<MysqlResultBinarySetRow>,
    },

    StmtPrepare {
        statement_id: u32,
        num_params: u16,
        params: Option<Vec<MysqlColumnDefinition>>,
        fields: Option<Vec<MysqlColumnDefinition>>,
    },
    StmtFetch,
}

#[derive(Debug)]
pub struct MysqlResponse {
    pub item: MysqlResponsePacket,
}

#[derive(Debug)]
pub enum MysqlBEMessage {
    HandshakeRequest(MysqlHandshakeRequest),
    Response(MysqlResponse),
}

#[derive(Debug)]
pub enum MysqlFEMessage {
    SSLRequest(MysqlSSLRequest),
    AuthRequest,
    Request(MysqlRequest),
    LocalFileData(usize),
    HandshakeResponse(MysqlHandshakeResponse),
}

fn parse_varint(i: &[u8]) -> IResult<&[u8], u64> {
    let (i, length) = be_u8(i)?;
    match length {
        // 251: NULL
        0xfb => Ok((i, 0)),
        // 252: value of following 2
        0xfc => {
            let (i, v0) = be_u8(i)?;
            let (i, v1) = be_u8(i)?;
            let v0 = v0 as u64;
            let v1 = (v1 as u64) << 8;
            Ok((i, v0 | v1))
        }
        // 253: value of following 3
        0xfd => {
            let (i, v0) = be_u8(i)?;
            let (i, v1) = be_u8(i)?;
            let (i, v2) = be_u8(i)?;
            let v0 = v0 as u64;
            let v1 = (v1 as u64) << 8;
            let v2 = (v2 as u64) << 16;
            Ok((i, v0 | v1 | v2))
        }
        // 254: value of following 8
        0xfe => {
            let (i, v0) = be_u8(i)?;
            let (i, v1) = be_u8(i)?;
            let (i, v2) = be_u8(i)?;
            let (i, v3) = be_u8(i)?;
            let (i, v4) = be_u8(i)?;
            let (i, v5) = be_u8(i)?;
            let (i, v6) = be_u8(i)?;
            let (i, v7) = be_u8(i)?;
            let v0 = v0 as u64;
            let v1 = (v1 as u64) << 8;
            let v2 = (v2 as u64) << 16;
            let v3 = (v3 as u64) << 24;
            let v4 = (v4 as u64) << 32;
            let v5 = (v5 as u64) << 40;
            let v6 = (v6 as u64) << 48;
            let v7 = (v7 as u64) << 56;
            Ok((i, v0 | v1 | v2 | v3 | v4 | v5 | v6 | v7))
        }
        _ => Ok((i, length as u64)),
    }
}

pub fn parse_packet_header(i: &[u8]) -> IResult<&[u8], MysqlPacket> {
    let mut payload = Vec::new();
    let mut payload_len: usize = 0;
    let mut rem = i;
    let mut pkt_num = None;
    // Loop until payload length is less than 0xffffff
    // https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_packets.html#sect_protocol_basic_packets_sending_mt_16mb
    loop {
        let (i, pkt_len) = verify(le_u24, |&pkt_len| -> bool { pkt_len <= PAYLOAD_MAX_LEN })(rem)?;
        payload_len += pkt_len as usize;
        let (i, num) = be_u8(i)?;
        if pkt_num.is_none() {
            pkt_num = Some(num);
        }
        let (i, rem_payload) = take(pkt_len)(i)?;
        rem = i;
        // payload extend rem_payload
        payload.extend_from_slice(rem_payload);

        if pkt_len < PAYLOAD_MAX_LEN {
            break;
        }
    }

    let pkt_len = payload_len;
    let pkt_num = pkt_num.unwrap_or_default();
    // payload extend rem for next parse
    let payload = Box::leak(payload.into_boxed_slice());
    Ok((
        rem,
        MysqlPacket {
            pkt_len,
            pkt_num,
            payload,
        },
    ))
}

fn parse_eof_packet(i: &[u8]) -> IResult<&[u8], MysqlEofPacket> {
    let (rem, header) = parse_packet_header(i)?;
    let payload =
        unsafe { std::slice::from_raw_parts(header.payload.as_ptr(), header.payload.len()) };
    let (i, _tag) = verify(be_u8, |&x| x == 0xfe)(payload)?;
    let (i, warnings) = le_u16(i)?;
    let (_, status_flags) = le_u16(i)?;

    Ok((
        rem,
        MysqlEofPacket {
            warnings,
            status_flags,
        },
    ))
}

fn parse_init_db_cmd(i: &[u8]) -> IResult<&[u8], MysqlCommand> {
    let (i, schema) = map(take(i.len()), |s: &[u8]| {
        String::from_utf8_lossy(s).to_string()
    })(i)?;
    Ok((i, MysqlCommand::InitDb { schema }))
}

fn parse_query_cmd(i: &[u8], client_flags: u32) -> IResult<&[u8], MysqlCommand> {
    let length = i.len();
    let old = i;
    let (i, param_cnt) = cond(client_flags & CLIENT_QUERY_ATTRIBUTES != 0, parse_varint)(i)?;
    let (i, _param_set_cnt) = cond(
        client_flags & CLIENT_QUERY_ATTRIBUTES != 0,
        verify(be_u8, |&param_set_cnt| param_set_cnt == 1),
    )(i)?;
    let param_cnt = param_cnt.unwrap_or_default();
    let (i, null_mask) = cond(param_cnt > 0, take((param_cnt + 7) / 8))(i)?;
    let (i, new_params_bind_flag) = cond(
        param_cnt > 0,
        verify(be_u8, |&new_params_bind_flag| new_params_bind_flag == 1),
    )(i)?;
    let new_params_bind_flag = new_params_bind_flag.unwrap_or_default();

    let (i, param_types) = cond(
        param_cnt > 0 && new_params_bind_flag != 0,
        many_m_n(
            param_cnt as usize,
            param_cnt as usize,
            |i| -> IResult<&[u8], (FieldType, bool)> {
                let (i, field_type) = be_u8(i)?;
                let (i, flags) = be_u8(i)?;
                let (i, _param_name) = map(take(length), |s: &[u8]| {
                    String::from_utf8_lossy(s).to_string()
                })(i)?;

                Ok((i, (parse_field_type(field_type), flags != 0)))
            },
        ),
    )(i)?;

    let mut data = i;
    if param_cnt > 0 {
        let null_mask = null_mask.unwrap_or_default();
        if let Some(param_types) = param_types {
            for i in 0..param_cnt as usize {
                if !null_mask.is_empty() && ((null_mask[i >> 3] >> (i & 7)) & 1) == 1 {
                    continue;
                }
                let (field_type, unsigned) = param_types.get(i).unwrap();

                let ch = data;
                // Normal
                let (ch, _res) = match *field_type {
                    FieldType::NULL => (ch, "NULL".to_string()),
                    FieldType::Tiny | FieldType::Bool => {
                        if *unsigned {
                            let (ch, v) = be_u8(ch)?;
                            (ch, v.to_string())
                        } else {
                            let (ch, v) = be_i8(ch)?;
                            (ch, v.to_string())
                        }
                    }
                    FieldType::Short | FieldType::Year => {
                        if *unsigned {
                            let (ch, v) = le_u16(ch)?;
                            (ch, v.to_string())
                        } else {
                            let (ch, v) = le_i16(ch)?;
                            (ch, v.to_string())
                        }
                    }
                    FieldType::Int24 | FieldType::Long => {
                        if *unsigned {
                            let (ch, v) = le_u32(ch)?;
                            (ch, v.to_string())
                        } else {
                            let (ch, v) = le_i32(ch)?;
                            (ch, v.to_string())
                        }
                    }
                    FieldType::LongLong => {
                        if *unsigned {
                            let (ch, v) = le_u64(ch)?;
                            (ch, v.to_string())
                        } else {
                            let (ch, v) = le_i64(ch)?;
                            (ch, v.to_string())
                        }
                    }
                    FieldType::Float => {
                        let (ch, v) = le_f32(ch)?;
                        (ch, v.to_string())
                    }
                    FieldType::Double => {
                        let (ch, v) = le_f64(ch)?;
                        (ch, v.to_string())
                    }
                    FieldType::Decimal
                    | FieldType::NewDecimal
                    | FieldType::Varchar
                    | FieldType::Bit
                    | FieldType::Enum
                    | FieldType::Set
                    | FieldType::TinyBlob
                    | FieldType::MediumBlob
                    | FieldType::LongBlob
                    | FieldType::Blob
                    | FieldType::VarString
                    | FieldType::String
                    | FieldType::Geometry
                    | FieldType::Json
                    | FieldType::Vector => {
                        let (ch, len) = parse_varint(ch)?;
                        let (ch, data) = map(take(len), |ch: &[u8]| {
                            String::from_utf8_lossy(ch).to_string()
                        })(ch)?;
                        (ch, data)
                    }
                    FieldType::Date
                    | FieldType::NewDate
                    | FieldType::Datetime
                    | FieldType::Datetime2
                    | FieldType::Timestamp
                    | FieldType::Timestamp2
                    | FieldType::Time
                    | FieldType::Time2 => {
                        let (ch, len) = parse_varint(ch)?;
                        match len {
                            0 => (ch, "datetime 0000-00-00 00:00:00.000000".to_string()),
                            4 => {
                                let (ch, year) = le_u16(ch)?;
                                let (ch, month) = be_u8(ch)?;
                                let (ch, day) = be_u8(ch)?;
                                (ch, format!("datetime {:04}-{:02}-{:02}", year, month, day))
                            }
                            7 => {
                                let (ch, year) = le_u16(ch)?;
                                let (ch, month) = be_u8(ch)?;
                                let (ch, day) = be_u8(ch)?;
                                let (ch, hour) = be_u8(ch)?;
                                let (ch, minute) = be_u8(ch)?;
                                let (ch, second) = be_u8(ch)?;
                                (
                                    ch,
                                    format!(
                                        "datetime {:04}-{:02}-{:02} {:02}:{:02}:{:02}",
                                        year, month, day, hour, minute, second
                                    ),
                                )
                            }
                            11 => {
                                let (ch, year) = le_u16(ch)?;
                                let (ch, month) = be_u8(ch)?;
                                let (ch, day) = be_u8(ch)?;
                                let (ch, hour) = be_u8(ch)?;
                                let (ch, minute) = be_u8(ch)?;
                                let (ch, second) = be_u8(ch)?;
                                let (ch, microsecond) = le_u32(ch)?;
                                (
                                    ch,
                                    format!(
                                        "datetime {:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:06}",
                                        year, month, day, hour, minute, second, microsecond,
                                    ),
                                )
                            }
                            _ => {
                                let (ch, _) = take(len)(ch)?;
                                (ch, "".to_string())
                            }
                        }
                    }
                    _ => (ch, "".to_string()),
                };
                data = ch;
            }
        }
    }
    let i = data;

    let consumed = old.len() - i.len();

    // Should never happen
    if consumed > length {
        return Ok((
            &[],
            MysqlCommand::Query {
                query: "".to_string(),
            },
        ));
    }
    let length = length - consumed;

    let (i, query) = map(take(length), |s: &[u8]| {
        String::from_utf8_lossy(s).to_string()
    })(i)?;

    Ok((i, MysqlCommand::Query { query }))
}

fn parse_stmt_prepare_cmd(i: &[u8]) -> IResult<&[u8], MysqlCommand> {
    let length = i.len();
    let (i, query) = map(take(length), |s: &[u8]| {
        String::from_utf8_lossy(s).to_string()
    })(i)?;
    Ok((i, MysqlCommand::StmtPrepare { query }))
}

fn parse_stmt_send_long_data_cmd(i: &[u8]) -> IResult<&[u8], MysqlCommand> {
    let (i, statement_id) = le_u32(i)?;
    let (i, param_id) = le_u16(i)?;
    let (i, length) = parse_varint(i)?;
    let (i, payload) = map(take(length), |s: &[u8]| {
        String::from_utf8_lossy(s).to_string()
    })(i)?;
    Ok((
        i,
        MysqlCommand::StmtSendLongData(StmtLongData {
            statement_id,
            param_id,
            payload,
        }),
    ))
}

fn parse_stmt_execute_cmd(
    i: &[u8], param_cnt: Option<u16>, param_types: Option<Vec<MysqlColumnDefinition>>,
    stmt_long_datas: Option<Vec<StmtLongData>>, client_flags: u32,
) -> IResult<&[u8], MysqlCommand> {
    let length = i.len();
    let old = i;
    let (i, statement_id) = le_u32(i)?;
    let (i, flags) = be_u8(i)?;
    let (i, _iteration_count) = le_u32(i)?;

    if let Some(param_cnt) = param_cnt {
        let mut param_cnt = param_cnt;
        if param_cnt > 0 || ((client_flags & CLIENT_QUERY_ATTRIBUTES != 0) && (flags & 8 != 0)) {
            let (i, override_param_cnts) =
                cond(client_flags & CLIENT_QUERY_ATTRIBUTES != 0, parse_varint)(i)?;
            if let Some(override_param_cnts) = override_param_cnts {
                param_cnt = override_param_cnts as u16;
            }
            if param_cnt > 0 {
                // NULL-bitmap, [(column-count + 7) / 8 bytes]
                let null_bitmap_size = (param_cnt + 7) / 8;
                let (i, null_mask) = take(null_bitmap_size)(i)?;
                let (i, new_params_bind_flags) = be_u8(i)?;

                let (i, new_param_types) = cond(
                    new_params_bind_flags != 0,
                    many_m_n(
                        param_cnt as usize,
                        param_cnt as usize,
                        |ch| -> IResult<&[u8], (FieldType, bool)> {
                            let (ch, field_type) = be_u8(ch)?;
                            let (ch, flags) = be_u8(ch)?;
                            let (ch, _param_names) =
                                cond(client_flags & CLIENT_QUERY_ATTRIBUTES != 0, |ch| {
                                    let (ch, length) = parse_varint(ch)?;
                                    let (ch, name) = map(take(length), |s| {
                                        String::from_utf8_lossy(s).to_string()
                                    })(ch)?;
                                    Ok((ch, name))
                                })(ch)?;

                            Ok((ch, (parse_field_type(field_type), flags != 0)))
                        },
                    ),
                )(i)?;
                let param_types = if let Some(new_param_types) = new_param_types {
                    Some(new_param_types)
                } else {
                    param_types.map(|param_types| {
                        param_types
                            .iter()
                            .map(|param_type| (param_type.field_type, param_type.flags != 0))
                            .collect()
                    })
                };

                let consumed = old.len() - i.len();
                // Should never happen
                if consumed > length {
                    return Ok((
                        &[],
                        MysqlCommand::StmtExecute {
                            statement_id,
                            params: None,
                        },
                    ));
                }
                let (i, data) = take(length - consumed)(i)?;
                if param_types.is_none() {
                    return Ok((
                        i,
                        MysqlCommand::StmtExecute {
                            statement_id,
                            params: None,
                        },
                    ));
                }

                let param_types = param_types.unwrap();

                let mut data = data;
                let mut params = Vec::new();
                for i in 0..param_cnt as usize {
                    // Field is NULL
                    // (byte >> bit-pos) % 2 == 1
                    if !null_mask.is_empty() && ((null_mask[i >> 3] >> (i & 7)) & 1) == 1 {
                        params.push("NULL".to_string());
                        continue;
                    }
                    // Field is LongData
                    if let Some(stmt_long_datas) = &stmt_long_datas {
                        for stmt_long_data in stmt_long_datas {
                            if stmt_long_data.param_id as usize == i {
                                params.push(stmt_long_data.payload.clone());
                                continue;
                            }
                        }
                    }
                    let (field_type, unsigned) = param_types.get(i).unwrap();

                    let ch = data;
                    // Normal
                    let (ch, res) = match *field_type {
                        FieldType::NULL => (ch, "NULL".to_string()),
                        FieldType::Tiny | FieldType::Bool => {
                            if *unsigned {
                                let (ch, v) = be_u8(ch)?;
                                (ch, v.to_string())
                            } else {
                                let (ch, v) = be_i8(ch)?;
                                (ch, v.to_string())
                            }
                        }
                        FieldType::Short | FieldType::Year => {
                            if *unsigned {
                                let (ch, v) = le_u16(ch)?;
                                (ch, v.to_string())
                            } else {
                                let (ch, v) = le_i16(ch)?;
                                (ch, v.to_string())
                            }
                        }
                        FieldType::Int24 | FieldType::Long => {
                            if *unsigned {
                                let (ch, v) = le_u32(ch)?;
                                (ch, v.to_string())
                            } else {
                                let (ch, v) = le_i32(ch)?;
                                (ch, v.to_string())
                            }
                        }
                        FieldType::LongLong => {
                            if *unsigned {
                                let (ch, v) = le_u64(ch)?;
                                (ch, v.to_string())
                            } else {
                                let (ch, v) = le_i64(ch)?;
                                (ch, v.to_string())
                            }
                        }
                        FieldType::Float => {
                            let (ch, v) = le_f32(ch)?;
                            (ch, v.to_string())
                        }
                        FieldType::Double => {
                            let (ch, v) = le_f64(ch)?;
                            (ch, v.to_string())
                        }
                        FieldType::Decimal
                        | FieldType::NewDecimal
                        | FieldType::Varchar
                        | FieldType::Bit
                        | FieldType::Enum
                        | FieldType::Set
                        | FieldType::TinyBlob
                        | FieldType::MediumBlob
                        | FieldType::LongBlob
                        | FieldType::Blob
                        | FieldType::VarString
                        | FieldType::String
                        | FieldType::Geometry
                        | FieldType::Json
                        | FieldType::Vector => {
                            let (ch, len) = parse_varint(ch)?;
                            let (ch, data) = map(take(len), |ch: &[u8]| {
                                String::from_utf8_lossy(ch).to_string()
                            })(ch)?;
                            (ch, data)
                        }
                        FieldType::Date
                        | FieldType::NewDate
                        | FieldType::Datetime
                        | FieldType::Datetime2
                        | FieldType::Timestamp
                        | FieldType::Timestamp2
                        | FieldType::Time
                        | FieldType::Time2 => {
                            let (ch, len) = parse_varint(ch)?;
                            match len {
                                0 => (ch, "datetime 0000-00-00 00:00:00.000000".to_string()),
                                4 => {
                                    let (ch, year) = le_u16(ch)?;
                                    let (ch, month) = be_u8(ch)?;
                                    let (ch, day) = be_u8(ch)?;
                                    (ch, format!("datetime {:04}-{:02}-{:02}", year, month, day))
                                }
                                7 => {
                                    let (ch, year) = le_u16(ch)?;
                                    let (ch, month) = be_u8(ch)?;
                                    let (ch, day) = be_u8(ch)?;
                                    let (ch, hour) = be_u8(ch)?;
                                    let (ch, minute) = be_u8(ch)?;
                                    let (ch, second) = be_u8(ch)?;
                                    (
                                        ch,
                                        format!(
                                            "datetime {:04}-{:02}-{:02} {:02}:{:02}:{:02}",
                                            year, month, day, hour, minute, second
                                        ),
                                    )
                                }
                                11 => {
                                    let (ch, year) = le_u16(ch)?;
                                    let (ch, month) = be_u8(ch)?;
                                    let (ch, day) = be_u8(ch)?;
                                    let (ch, hour) = be_u8(ch)?;
                                    let (ch, minute) = be_u8(ch)?;
                                    let (ch, second) = be_u8(ch)?;
                                    let (ch, microsecond) = le_u32(ch)?;
                                    (
                                        ch,
                                        format!(
                                            "datetime {:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:06}",
                                            year, month, day, hour, minute, second, microsecond,
                                        ),
                                    )
                                }
                                _ => {
                                    let (ch, _) = take(len)(ch)?;
                                    (ch, "".to_string())
                                }
                            }
                        }
                        _ => (ch, "".to_string()),
                    };
                    params.push(res);
                    data = ch;
                }
                Ok((
                    i,
                    MysqlCommand::StmtExecute {
                        statement_id,
                        params: Some(params),
                    },
                ))
            } else {
                Ok((
                    i,
                    MysqlCommand::StmtExecute {
                        statement_id,
                        params: None,
                    },
                ))
            }
        } else {
            Ok((
                i,
                MysqlCommand::StmtExecute {
                    statement_id,
                    params: None,
                },
            ))
        }
    } else {
        let consumed = old.len() - i.len();
        // Should never happen
        if consumed > length {
            return Ok((
                &[],
                MysqlCommand::StmtExecute {
                    statement_id,
                    params: None,
                },
            ));
        }
        let (i, _) = take(length - consumed)(i)?;
        Ok((
            i,
            MysqlCommand::StmtExecute {
                statement_id,
                params: None,
            },
        ))
    }
}

fn parse_field_list_cmd(i: &[u8]) -> IResult<&[u8], MysqlCommand> {
    let length = i.len();
    let old = i;
    let (i, table) = map(take_till(|ch| ch == 0x00), |s: &[u8]| {
        String::from_utf8_lossy(s).to_string()
    })(i)?;
    let consumed = old.len() - i.len();
    // Should never happen
    if consumed > length {
        return Ok((
            &[],
            MysqlCommand::FieldList {
                table: "".to_string(),
            },
        ));
    }
    let (i, _) = take(length - consumed)(i)?;
    Ok((i, MysqlCommand::FieldList { table }))
}

fn parse_stmt_fetch_cmd(i: &[u8]) -> IResult<&[u8], MysqlCommand> {
    let (i, statement_id) = le_u32(i)?;
    let (i, number_rows) = le_u32(i)?;
    Ok((
        i,
        MysqlCommand::StmtFetch {
            statement_id,
            number_rows,
        },
    ))
}

fn parse_stmt_close_cmd(i: &[u8]) -> IResult<&[u8], MysqlCommand> {
    let (i, statement_id) = le_u32(i)?;
    Ok((i, MysqlCommand::StmtClose { statement_id }))
}

fn parse_column_definition(i: &[u8]) -> IResult<&[u8], MysqlColumnDefinition> {
    let (rem, header) = parse_packet_header(i)?;
    let payload =
        unsafe { std::slice::from_raw_parts(header.payload.as_ptr(), header.payload.len()) };
    let (i, _len) = parse_varint(payload)?;
    let (i, _catalog) = map(take(_len as u32), |s: &[u8]| {
        String::from_utf8_lossy(s).to_string()
    })(i)?;

    let (i, _len) = parse_varint(i)?;
    let (i, schema) = map(take(_len as u32), |s: &[u8]| {
        String::from_utf8_lossy(s).to_string()
    })(i)?;

    let (i, _len) = parse_varint(i)?;
    let (i, table) = map(take(_len as u32), |s: &[u8]| {
        String::from_utf8_lossy(s).to_string()
    })(i)?;

    let (i, _len) = parse_varint(i)?;
    let (i, orig_table) = map(take(_len as u32), |s: &[u8]| {
        String::from_utf8_lossy(s).to_string()
    })(i)?;

    let (i, _len) = parse_varint(i)?;
    let (i, name) = map(take(_len as u32), |s: &[u8]| {
        String::from_utf8_lossy(s).to_string()
    })(i)?;

    let (i, _len) = parse_varint(i)?;
    let (i, _orig_name) = map(take(_len as u32), |s: &[u8]| {
        String::from_utf8_lossy(s).to_string()
    })(i)?;

    let (i, _) = parse_varint(i)?;
    let (i, character_set) = le_u16(i)?;
    let (i, column_length) = le_u32(i)?;
    let (i, field_type) = be_u8(i)?;
    let (i, flags) = le_u16(i)?;
    let (i, decimals) = be_u8(i)?;
    let (_, _filter) = take(2_u32)(i)?;

    let field_type = parse_field_type(field_type);

    Ok((
        rem,
        MysqlColumnDefinition {
            catalog: "def".to_string(),
            schema,
            table,
            orig_table,
            name,
            character_set,
            column_length,
            field_type,
            flags,
            decimals,
        },
    ))
}

fn parse_resultset_row_texts(i: &[u8]) -> IResult<&[u8], Vec<String>> {
    let mut rem = i;
    let mut length = i.len();
    let mut texts = Vec::new();
    while length > 0 {
        let (i, len) = parse_varint(rem)?;
        let mut consumed = rem.len() - i.len();
        if len == 0xFB {
            texts.push("NULL".to_string());
            rem = i;
        } else {
            let (i, text) = map(take(len), |s: &[u8]| String::from_utf8_lossy(s).to_string())(i)?;
            texts.push(text);
            consumed += len as usize;
            rem = i;
        }
        // Should never happen
        if consumed > length {
            return Ok((&[], texts));
        }
        length -= consumed;
    }

    Ok((&[], texts))
}

fn parse_resultset_row(i: &[u8]) -> IResult<&[u8], MysqlResultSetRow> {
    let (rem, header) = parse_packet_header(i)?;
    let payload =
        unsafe { std::slice::from_raw_parts(header.payload.as_ptr(), header.payload.len()) };
    let (_, texts) = parse_resultset_row_texts(payload)?;

    Ok((rem, MysqlResultSetRow { texts }))
}

fn parse_binary_resultset_row(
    columns: Vec<MysqlColumnDefinition>,
) -> impl FnMut(&[u8]) -> IResult<&[u8], MysqlResultBinarySetRow> {
    move |i| {
        let (rem, header) = parse_packet_header(i)?;
        let payload =
            unsafe { std::slice::from_raw_parts(header.payload.as_ptr(), header.payload.len()) };
        let (i, response_code) = verify(be_u8, |&x| x == 0x00 || x == 0xFF)(payload)?;
        // ERR
        if response_code == 0xFF {
            let (_, _resp) = parse_response_err(i)?;
            return Ok((rem, MysqlResultBinarySetRow::Err));
        }
        let (_, data) = take(header.pkt_len - 1)(i)?;

        // NULL-bitmap, [(column-count + 7 + 2) / 8 bytes]
        let mut texts = Vec::new();
        let mut pos = (columns.len() + 7 + 2) >> 3;
        let null_mask = &data[..pos];
        for i in 0..columns.len() {
            // Field is NULL
            // byte = ((field-pos + 2) / 8)
            // bit-pos = ((field-pos + 2) % 8)
            // (byte >> bit-pos) % 2 == 1
            if ((null_mask[(i + 2) >> 3] >> ((i + 2) & 7)) & 1) == 1 {
                continue;
            }

            match columns[i].field_type {
                FieldType::NULL => texts.push("NULL".to_string()),
                FieldType::Tiny => {
                    if columns[i].flags & (FIELD_FLAGS_UNSIGNED as u16) != 0 {
                        texts.push(format!("{}", data[pos].to_u8().unwrap_or_default()));
                    } else {
                        texts.push(format!("{}", data[pos].to_i8().unwrap_or_default()));
                    }
                    pos += 1;
                }
                FieldType::Short | FieldType::Year => {
                    if columns[i].flags & (FIELD_FLAGS_UNSIGNED as u16) != 0 {
                        texts.push(format!(
                            "{}",
                            u16::from_le_bytes(data[pos..pos + 2].try_into().unwrap_or_default())
                        ));
                    } else {
                        texts.push(format!(
                            "{}",
                            i16::from_le_bytes(data[pos..pos + 2].try_into().unwrap_or_default())
                        ));
                    }
                    pos += 2;
                }
                FieldType::Int24 | FieldType::Long => {
                    if columns[i].flags & (FIELD_FLAGS_UNSIGNED as u16) != 0 {
                        texts.push(format!(
                            "{}",
                            u32::from_le_bytes(data[pos..pos + 4].try_into().unwrap_or_default())
                        ));
                    } else {
                        texts.push(format!(
                            "{}",
                            i32::from_le_bytes(data[pos..pos + 4].try_into().unwrap_or_default())
                        ));
                    }
                    pos += 4;
                }
                FieldType::LongLong => {
                    if columns[i].flags & (FIELD_FLAGS_UNSIGNED as u16) != 0 {
                        texts.push(format!(
                            "{}",
                            u64::from_le_bytes(data[pos..pos + 8].try_into().unwrap_or_default())
                        ));
                    } else {
                        texts.push(format!(
                            "{}",
                            i64::from_le_bytes(data[pos..pos + 8].try_into().unwrap_or_default())
                        ));
                    }
                    pos += 8;
                }
                FieldType::Float => {
                    texts.push(format!(
                        "{}",
                        f32::from_le_bytes(data[pos..pos + 4].try_into().unwrap_or_default())
                    ));
                    pos += 4;
                }
                FieldType::Double => {
                    texts.push(format!(
                        "{}",
                        f64::from_le_bytes(data[pos..pos + 8].try_into().unwrap_or_default())
                    ));
                    pos += 8;
                }
                FieldType::Decimal
                | FieldType::NewDecimal
                | FieldType::Varchar
                | FieldType::Bit
                | FieldType::Enum
                | FieldType::Set
                | FieldType::TinyBlob
                | FieldType::MediumBlob
                | FieldType::LongBlob
                | FieldType::Blob
                | FieldType::VarString
                | FieldType::String
                | FieldType::Geometry
                | FieldType::Json
                | FieldType::Vector => {
                    let length_string = &data[pos..];
                    let (not_readed, length) = parse_varint(length_string)?;
                    if length_string.len() < length as usize {
                        break;
                    }
                    pos += length_string.len() - not_readed.len();
                    if length > 0 {
                        let (_, string) =
                            map(take(length), |s| String::from_utf8_lossy(s).to_string())(
                                not_readed,
                            )?;
                        texts.push(string);
                        pos += length as usize;
                    }
                }
                FieldType::Date
                | FieldType::NewDate
                | FieldType::Datetime
                | FieldType::Datetime2
                | FieldType::Timestamp
                | FieldType::Timestamp2
                | FieldType::Time
                | FieldType::Time2 => {
                    let length_string = &data[pos..];
                    let (not_readed, length) = parse_varint(length_string)?;
                    if length_string.len() < length as usize {
                        break;
                    }
                    pos += length_string.len() - not_readed.len();
                    let string = match length {
                        0 => "datetime 0000-00-00 00:00:00.000000".to_string(),
                        4 => {
                            let (ch, year) = le_u16(not_readed)?;
                            let (ch, month) = be_u8(ch)?;
                            let (_, day) = be_u8(ch)?;
                            format!("datetime {:04}-{:02}-{:02}", year, month, day)
                        }
                        7 => {
                            let (ch, year) = le_u16(not_readed)?;
                            let (ch, month) = be_u8(ch)?;
                            let (ch, day) = be_u8(ch)?;
                            let (ch, hour) = be_u8(ch)?;
                            let (ch, minute) = be_u8(ch)?;
                            let (_, second) = be_u8(ch)?;
                            format!(
                                "datetime {:04}-{:02}-{:02} {:02}:{:02}:{:02}",
                                year, month, day, hour, minute, second
                            )
                        }
                        11 => {
                            let (ch, year) = le_u16(not_readed)?;
                            let (ch, month) = be_u8(ch)?;
                            let (ch, day) = be_u8(ch)?;
                            let (ch, hour) = be_u8(ch)?;
                            let (ch, minute) = be_u8(ch)?;
                            let (ch, second) = be_u8(ch)?;
                            let (_, microsecond) = le_u32(ch)?;
                            format!(
                                "datetime {:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:06}",
                                year, month, day, hour, minute, second, microsecond,
                            )
                        }
                        _ => "".to_string(),
                    };
                    pos += length as usize;
                    texts.push(string);
                }
                _ => {
                    break;
                }
            }
        }
        let texts = texts.join(",");

        Ok((rem, MysqlResultBinarySetRow::Text(texts)))
    }
}

fn parse_response_resultset(i: &[u8], n_cols: u64) -> IResult<&[u8], MysqlResponse> {
    let (i, columns) = many_m_n(n_cols as usize, n_cols as usize, parse_column_definition)(i)?;
    let (i, eof) = parse_eof_packet(i)?;
    let (i, (rows, _)) = many_till(parse_resultset_row, |i| {
        let (rem, header) = parse_packet_header(i)?;
        let payload =
            unsafe { std::slice::from_raw_parts(header.payload.as_ptr(), header.payload.len()) };
        let (i, response_code) = verify(be_u8, |&x| x == 0xFE || x == 0xFF)(payload)?;
        match response_code {
            // EOF
            0xFE => Ok((
                rem,
                MysqlResponse {
                    item: MysqlResponsePacket::EOF,
                },
            )),
            // ERR
            0xFF => {
                let (_, response) = parse_response_err(i)?;
                Ok((rem, response))
            }
            _ => Ok((
                rem,
                MysqlResponse {
                    item: MysqlResponsePacket::Unknown,
                },
            )),
        }
    })(i)?;
    Ok((
        i,
        MysqlResponse {
            item: MysqlResponsePacket::ResultSet {
                n_cols,
                columns,
                eof,
                rows,
            },
        },
    ))
}

fn parse_response_binary_resultset(i: &[u8], n_cols: u64) -> IResult<&[u8], MysqlResponse> {
    let (i, columns) = many_m_n(n_cols as usize, n_cols as usize, parse_column_definition)(i)?;
    let (i, eof) = parse_eof_packet(i)?;
    let (i, (rows, _)) = many_till(parse_binary_resultset_row(columns), |i| {
        // eof
        let (rem, header) = parse_packet_header(i)?;
        let payload =
            unsafe { std::slice::from_raw_parts(header.payload.as_ptr(), header.payload.len()) };
        let (i, response_code) = verify(be_u8, |&x| x == 0xFE || x == 0xFF)(payload)?;
        match response_code {
            // EOF
            0xFE => Ok((
                rem,
                MysqlResponse {
                    item: MysqlResponsePacket::EOF,
                },
            )),
            // ERR
            0xFF => {
                let (_, response) = parse_response_err(i)?;
                Ok((rem, response))
            }
            _ => Ok((
                rem,
                MysqlResponse {
                    item: MysqlResponsePacket::Unknown,
                },
            )),
        }
    })(i)?;
    Ok((
        i,
        MysqlResponse {
            item: MysqlResponsePacket::BinaryResultSet { n_cols, eof, rows },
        },
    ))
}

fn parse_response_ok(i: &[u8]) -> IResult<&[u8], MysqlResponse> {
    let length = i.len();
    let old = i;
    let (i, rows) = parse_varint(i)?;
    let (i, _last_insert_id) = parse_varint(i)?;
    let (i, flags) = le_u16(i)?;
    let (i, warnings) = le_u16(i)?;
    let consumed = old.len() - i.len();
    // Should never happen
    if consumed > length {
        return Ok((
            &[],
            MysqlResponse {
                item: MysqlResponsePacket::Ok {
                    rows,
                    flags,
                    warnings,
                },
            },
        ));
    }
    let (i, _) = take(length - consumed)(i)?;

    Ok((
        i,
        MysqlResponse {
            item: MysqlResponsePacket::Ok {
                rows,
                flags,
                warnings,
            },
        },
    ))
}

fn parse_response_err(i: &[u8]) -> IResult<&[u8], MysqlResponse> {
    let length = i.len();
    let (i, error_code) = le_u16(i)?;
    let (i, _) = take(6_u32)(i)?;
    // sql state maker & sql state
    let (i, _) = take(6_u32)(i)?;
    let length = length - 2 - 12;
    let (i, error_message) = map(take(length), |s: &[u8]| {
        String::from_utf8_lossy(s).to_string()
    })(i)?;
    Ok((
        i,
        MysqlResponse {
            item: MysqlResponsePacket::Err {
                error_code,
                error_message,
            },
        },
    ))
}

pub fn parse_handshake_request(i: &[u8]) -> IResult<&[u8], MysqlHandshakeRequest> {
    let (rem, header) = parse_packet_header(i)?;
    let payload =
        unsafe { std::slice::from_raw_parts(header.payload.as_ptr(), header.payload.len()) };
    let (i, protocol) = verify(be_u8, |&x| x == 0x0a_u8)(payload)?;
    let (i, version) = map(take_till(|ch| ch == 0x00), |s: &[u8]| {
        String::from_utf8_lossy(s).to_string()
    })(i)?;
    let (i, _) = take(1_u32)(i)?;
    let (i, conn_id) = le_u32(i)?;
    let (i, salt1) = map(take(8_u32), |s: &[u8]| {
        String::from_utf8_lossy(s).to_string()
    })(i)?;
    let (i, _) = take(1_u32)(i)?;
    let (i, capability_flags1) = le_u16(i)?;
    let (i, character_set) = be_u8(i)?;
    let (i, status_flags) = le_u16(i)?;
    let (i, capability_flags2) = le_u16(i)?;
    let (i, auth_plugin_len) = be_u8(i)?;
    let (i, _) = take(10_u32)(i)?;
    let (i, salt2) = map(take_till(|ch| ch == 0x00), |s: &[u8]| {
        String::from_utf8_lossy(s).to_string()
    })(i)?;
    let (i, _) = take(1_u32)(i)?;
    let (i, auth_plugin_data) = cond(
        auth_plugin_len > 0,
        map(take(auth_plugin_len as usize), |s: &[u8]| {
            String::from_utf8_lossy(s).to_string()
        }),
    )(i)?;
    let (_, _) = take(1_u32)(i)?;
    Ok((
        rem,
        MysqlHandshakeRequest {
            protocol,
            version,
            conn_id,
            salt1,
            capability_flags1,
            character_set,
            status_flags,
            capability_flags2,
            auth_plugin_len,
            salt2,
            auth_plugin_data,
        },
    ))
}

pub fn parse_handshake_capabilities(i: &[u8]) -> IResult<&[u8], u32> {
    let (rem, header) = parse_packet_header(i)?;
    let payload =
        unsafe { std::slice::from_raw_parts(header.payload.as_ptr(), header.payload.len()) };
    let (i, client_flags) = verify(le_u32, |&client_flags| {
        client_flags & CLIENT_PROTOCOL_41 != 0
    })(payload)?;
    let (i, _max_packet_size) = be_u32(i)?;
    let (_, _character_set) = be_u8(i)?;

    // fk this code
    Ok((rem, client_flags))
}

pub fn parse_handshake_ssl_request(i: &[u8]) -> IResult<&[u8], MysqlSSLRequest> {
    let (rem, header) = parse_packet_header(i)?;
    let payload =
        unsafe { std::slice::from_raw_parts(header.payload.as_ptr(), header.payload.len()) };
    let (i, _client_flags) = verify(le_u32, |&client_flags| {
        client_flags & CLIENT_PROTOCOL_41 != 0
    })(payload)?;
    let (i, _max_packet_size) = be_u32(i)?;
    let (i, _character_set) = be_u8(i)?;
    let (_, filter) = map(take(23_u32), |s: &[u8]| {
        String::from_utf8_lossy(s).to_string()
    })(i)?;
    Ok((
        rem,
        MysqlSSLRequest {
            filter: Some(filter),
        },
    ))
}

pub fn parse_handshake_response(i: &[u8]) -> IResult<&[u8], MysqlHandshakeResponse> {
    let (rem, header) = parse_packet_header(i)?;
    let payload =
        unsafe { std::slice::from_raw_parts(header.payload.as_ptr(), header.payload.len()) };
    let (i, client_flags) = verify(le_u32, |&client_flags| {
        client_flags & CLIENT_PROTOCOL_41 != 0
    })(payload)?;
    let (i, _max_packet_size) = be_u32(i)?;
    let (i, _character_set) = be_u8(i)?;

    let (i, _filter) = map(take(23_u32), |s: &[u8]| {
        String::from_utf8_lossy(s).to_string()
    })(i)?;
    let (i, username) = map(take_till(|ch| ch == 0x00), |s: &[u8]| {
        String::from_utf8_lossy(s).to_string()
    })(i)?;
    let (i, _) = take(1_u32)(i)?;
    let (i, auth_response_len) = be_u8(i)?;
    let (i, auth_response) = map(take(auth_response_len as usize), |s: &[u8]| {
        String::from_utf8_lossy(s).to_string()
    })(i)?;

    let (i, database) = cond(
        client_flags & CLIENT_CONNECT_WITH_DB != 0,
        map(take_till(|ch| ch == 0x00), |s: &[u8]| {
            String::from_utf8_lossy(s).to_string()
        }),
    )(i)?;
    let (i, _) = cond(database.is_some(), take(1_u32))(i)?;

    let (i, client_plugin_name) = cond(
        client_flags & CLIENT_PLUGIN_AUTH != 0,
        map(take_till(|ch| ch == 0x00), |s: &[u8]| {
            String::from_utf8_lossy(s).to_string()
        }),
    )(i)?;
    let (i, _) = cond(client_plugin_name.is_some(), take(1_u32))(i)?;

    let (i, length) = cond(client_flags & CLIENT_CONNECT_ATTRS != 0, be_u8)(i)?;

    let (i, attributes) = cond(
        length.is_some(),
        parse_handshake_response_attributes(length),
    )(i)?;

    let (_, zstd_compression_level) =
        cond(client_flags & CLIENT_ZSTD_COMPRESSION_ALGORITHM != 0, be_u8)(i)?;
    Ok((
        rem,
        MysqlHandshakeResponse {
            username,
            auth_response_len,
            auth_response,
            database,
            client_plugin_name,
            attributes,
            zstd_compression_level,
            client_flags,
        },
    ))
}

fn parse_handshake_response_attributes(
    length: Option<u8>,
) -> impl FnMut(&[u8]) -> IResult<&[u8], Vec<MysqlHandshakeResponseAttribute>> {
    move |i| {
        if length.is_none() {
            return Ok((i, Vec::new()));
        }
        let mut length = length.unwrap();
        let mut res = vec![];
        let mut rem = i;
        while length > 0 {
            let (i, key_len) = be_u8(rem)?;
            // length contains key_len
            length -= 1;
            let (i, key) = map(take(key_len as usize), |s: &[u8]| {
                String::from_utf8_lossy(s).to_string()
            })(i)?;
            let (i, value_len) = be_u8(i)?;
            // length contains value_len
            length -= 1;
            let (i, value) = map(take(value_len as usize), |s: &[u8]| {
                String::from_utf8_lossy(s).to_string()
            })(i)?;
            res.push(MysqlHandshakeResponseAttribute { key, value });
            length -= key_len + value_len;
            rem = i;
        }

        Ok((rem, res))
    }
}

pub fn parse_auth_response(i: &[u8]) -> IResult<&[u8], MysqlResponse> {
    let (rem, header) = parse_packet_header(i)?;
    let payload =
        unsafe { std::slice::from_raw_parts(header.payload.as_ptr(), header.payload.len()) };
    let (i, status) = be_u8(payload)?;
    match status {
        0x00 => {
            let (_, response) = parse_response_ok(i)?;
            Ok((rem, response))
        }
        // AuthMoreData
        0x01 => {
            let (_i, data) = be_u8(i)?;
            Ok((
                rem,
                MysqlResponse {
                    item: MysqlResponsePacket::AuthMoreData { data },
                },
            ))
        }
        0xEF => Ok((
            rem,
            MysqlResponse {
                item: MysqlResponsePacket::EOF,
            },
        )),
        _ => Ok((
            rem,
            MysqlResponse {
                item: MysqlResponsePacket::Unknown,
            },
        )),
    }
}

pub fn parse_auth_switch_request(i: &[u8]) -> IResult<&[u8], MysqlAuthSwtichRequest> {
    let (rem, header) = parse_packet_header(i)?;
    let payload =
        unsafe { std::slice::from_raw_parts(header.payload.as_ptr(), header.payload.len()) };
    let plugin_length = payload.len();
    let (i, plugin_name) = map(take_till(|ch| ch == 0x00), |s: &[u8]| {
        String::from_utf8_lossy(s).to_string()
    })(payload)?;
    let plugin_length = plugin_length - i.len();
    let (_, plugin_data) = map(
        cond(
            header.pkt_len - (plugin_length) > 0,
            take(header.pkt_len - plugin_length),
        ),
        |ch: Option<&[u8]>| {
            if let Some(ch) = ch {
                String::from_utf8_lossy(ch).to_string()
            } else {
                String::new()
            }
        },
    )(i)?;

    Ok((
        rem,
        MysqlAuthSwtichRequest {
            plugin_name,
            plugin_data,
        },
    ))
}

pub fn parse_local_file_data_content(i: &[u8]) -> IResult<&[u8], usize> {
    let (rem, header) = parse_packet_header(i)?;
    Ok((rem, header.pkt_len))
}

pub fn parse_request(
    i: &[u8], params: Option<u16>, param_types: Option<Vec<MysqlColumnDefinition>>,
    stmt_long_datas: Option<Vec<StmtLongData>>, client_flags: u32,
) -> IResult<&[u8], MysqlRequest> {
    let (rem, header) = parse_packet_header(i)?;
    let payload =
        unsafe { std::slice::from_raw_parts(header.payload.as_ptr(), header.payload.len()) };
    let (i, command_code) = be_u8(payload)?;
    match command_code {
        0x01 => Ok((
            rem,
            MysqlRequest {
                command_code,
                command: MysqlCommand::Quit,
            },
        )),

        0x02 => {
            let (_, command) = parse_init_db_cmd(i)?;
            Ok((
                rem,
                MysqlRequest {
                    command_code,
                    command,
                },
            ))
        }

        0x03 => {
            let (_, command) = parse_query_cmd(i, client_flags)?;
            Ok((
                rem,
                MysqlRequest {
                    command_code,
                    command,
                },
            ))
        }

        0x04 => {
            let (_, command) = parse_field_list_cmd(i)?;
            Ok((
                rem,
                MysqlRequest {
                    command_code,
                    command,
                },
            ))
        }

        0x08 => Ok((
            rem,
            MysqlRequest {
                command_code,
                command: MysqlCommand::Statistics,
            },
        )),

        0x0D => Ok((
            rem,
            MysqlRequest {
                command_code,
                command: MysqlCommand::Debug,
            },
        )),

        0x0e => Ok((
            rem,
            MysqlRequest {
                command_code,
                command: MysqlCommand::Ping,
            },
        )),

        0x11 => Ok((
            rem,
            MysqlRequest {
                command_code,
                command: MysqlCommand::ChangeUser,
            },
        )),
        0x1A => {
            let length = header.pkt_len - 1;
            if length == 2 {
                let (_, _) = le_u16(i)?;
                Ok((
                    rem,
                    MysqlRequest {
                        command_code,
                        command: MysqlCommand::SetOption,
                    },
                ))
            } else if length == 4 {
                let (_, statement_id) = le_u32(i)?;
                Ok((
                    rem,
                    MysqlRequest {
                        command_code,
                        command: MysqlCommand::StmtReset { statement_id },
                    },
                ))
            } else {
                Ok((
                    rem,
                    MysqlRequest {
                        command_code,
                        command: MysqlCommand::Unknown,
                    },
                ))
            }
        }

        0x1F => Ok((
            rem,
            MysqlRequest {
                command_code,
                command: MysqlCommand::ResetConnection,
            },
        )),

        0x16 => {
            let (_, command) = parse_stmt_prepare_cmd(i)?;
            Ok((
                rem,
                MysqlRequest {
                    command_code,
                    command,
                },
            ))
        }

        0x17 => {
            let (_, command) =
                parse_stmt_execute_cmd(i, params, param_types, stmt_long_datas, client_flags)?;
            Ok((
                rem,
                MysqlRequest {
                    command_code,
                    command,
                },
            ))
        }

        0x18 => {
            let (_, command) = parse_stmt_send_long_data_cmd(i)?;
            Ok((
                rem,
                MysqlRequest {
                    command_code,
                    command,
                },
            ))
        }

        0x19 => {
            //
            if header.pkt_len - 1 == 8 {
                let (_, command) = parse_stmt_fetch_cmd(i)?;
                Ok((
                    rem,
                    MysqlRequest {
                        command_code,
                        command,
                    },
                ))
            } else {
                let (_, command) = parse_stmt_close_cmd(i)?;
                Ok((
                    rem,
                    MysqlRequest {
                        command_code,
                        command,
                    },
                ))
            }
        }

        _ => {
            SCLogDebug!(
                "Unknown request, header: {:?}, command_code: {}",
                header,
                command_code
            );
            let (_, _) = cond(header.pkt_len - 1 > 0, take(header.pkt_len - 1))(i)?;
            Ok((
                rem,
                MysqlRequest {
                    command_code,
                    command: MysqlCommand::Unknown,
                },
            ))
        }
    }
}

pub fn parse_response(i: &[u8]) -> IResult<&[u8], MysqlResponse> {
    let (rem, header) = parse_packet_header(i)?;
    let payload =
        unsafe { std::slice::from_raw_parts(header.payload.as_ptr(), header.payload.len()) };
    let (i, response_code) = be_u8(payload)?;
    match response_code {
        // OK
        0x00 => {
            let (_, response) = parse_response_ok(i)?;
            Ok((rem, response))
        }
        // LOCAL INFILE Request
        0xFB => Ok((
            rem,
            MysqlResponse {
                item: MysqlResponsePacket::LocalInFileRequest,
            },
        )),
        // EOF
        0xFE => Ok((
            rem,
            MysqlResponse {
                item: MysqlResponsePacket::EOF,
            },
        )),
        // ERR
        0xFF => {
            let (_, response) = parse_response_err(i)?;
            Ok((rem, response))
        }
        // Text Resultset
        _ => parse_response_resultset(rem, response_code as u64),
    }
}

pub fn parse_change_user_response(i: &[u8]) -> IResult<&[u8], MysqlResponse> {
    let (rem, header) = parse_packet_header(i)?;
    let payload =
        unsafe { std::slice::from_raw_parts(header.payload.as_ptr(), header.payload.len()) };
    let (i, response_code) = be_u8(payload)?;
    match response_code {
        // OK
        0x00 => {
            let (_, response) = parse_response_ok(i)?;
            Ok((rem, response))
        }
        // AuthSwitch
        0xFE => Ok((
            rem,
            MysqlResponse {
                item: MysqlResponsePacket::AuthSwithRequest,
            },
        )),
        // ERR
        0xFF => {
            let (_, response) = parse_response_err(i)?;
            Ok((rem, response))
        }
        _ => Ok((
            rem,
            MysqlResponse {
                item: MysqlResponsePacket::Unknown,
            },
        )),
    }
}

pub fn parse_statistics_response(i: &[u8]) -> IResult<&[u8], MysqlResponse> {
    let (rem, header) = parse_packet_header(i)?;
    let payload =
        unsafe { std::slice::from_raw_parts(header.payload.as_ptr(), header.payload.len()) };
    let (_, _) = take(header.pkt_len)(payload)?;
    Ok((
        rem,
        MysqlResponse {
            item: MysqlResponsePacket::Statistics,
        },
    ))
}

pub fn parse_field_list_response(i: &[u8]) -> IResult<&[u8], MysqlResponse> {
    let (rem, header) = parse_packet_header(i)?;
    let payload =
        unsafe { std::slice::from_raw_parts(header.payload.as_ptr(), header.payload.len()) };
    let (i, response_code) = be_u8(payload)?;
    match response_code {
        // ERR
        0xFF => {
            let (_, response) = parse_response_err(i)?;
            Ok((rem, response))
        }
        0x00 => Ok((
            rem,
            MysqlResponse {
                item: MysqlResponsePacket::FieldsList { columns: None },
            },
        )),
        _ => {
            let n_cols = response_code;
            let (i, columns) =
                many_m_n(n_cols as usize, n_cols as usize, parse_column_definition)(rem)?;
            let (_, _) = parse_eof_packet(i)?;
            Ok((
                rem,
                MysqlResponse {
                    item: MysqlResponsePacket::FieldsList {
                        columns: Some(columns),
                    },
                },
            ))
        }
    }
}

pub fn parse_stmt_prepare_response(i: &[u8], _client_flags: u32) -> IResult<&[u8], MysqlResponse> {
    let (rem, header) = parse_packet_header(i)?;
    let payload =
        unsafe { std::slice::from_raw_parts(header.payload.as_ptr(), header.payload.len()) };
    let (i, response_code) = be_u8(payload)?;
    match response_code {
        0x00 => {
            let (i, statement_id) = le_u32(i)?;
            let (i, num_columns) = le_u16(i)?;
            let (i, num_params) = le_u16(i)?;
            let (i, _filter) = be_u8(i)?;
            //TODO: why?
            // let (i, _warning_cnt) = cond(header.pkt_len > 12, take(2_u32))(i)?;
            let (_, _warning_cnt) = take(2_u32)(i)?;
            // should use remain
            let (i, params) = cond(
                num_params > 0,
                many_till(parse_column_definition, parse_eof_packet),
            )(rem)
            .map(|(i, params)| {
                if let Some(params) = params {
                    (i, Some(params.0))
                } else {
                    (i, None)
                }
            })?;
            // should use remain
            let (_, fields) = cond(
                num_columns > 0,
                many_till(parse_column_definition, parse_eof_packet),
            )(i)
            .map(|(i, fields)| {
                if let Some(fields) = fields {
                    (i, Some(fields.0))
                } else {
                    (i, None)
                }
            })?;

            Ok((
                i,
                MysqlResponse {
                    item: MysqlResponsePacket::StmtPrepare {
                        statement_id,
                        num_params,
                        params,
                        fields,
                    },
                },
            ))
        }
        // ERR
        0xFF => {
            let (_, response) = parse_response_err(i)?;
            Ok((rem, response))
        }
        _ => Ok((
            rem,
            MysqlResponse {
                item: MysqlResponsePacket::Unknown,
            },
        )),
    }
}

pub fn parse_stmt_execute_response(i: &[u8]) -> IResult<&[u8], MysqlResponse> {
    let (rem, header) = parse_packet_header(i)?;
    let payload =
        unsafe { std::slice::from_raw_parts(header.payload.as_ptr(), header.payload.len()) };
    let (i, response_code) = be_u8(payload)?;
    match response_code {
        // OK
        0x00 => {
            let (_, response) = parse_response_ok(i)?;
            Ok((rem, response))
        }
        // ERR
        0xFF => {
            let (_, response) = parse_response_err(i)?;
            Ok((rem, response))
        }
        _ => parse_response_binary_resultset(rem, response_code as u64),
    }
}

pub fn parse_stmt_fetch_response(i: &[u8]) -> IResult<&[u8], MysqlResponse> {
    let (rem, header) = parse_packet_header(i)?;
    let payload =
        unsafe { std::slice::from_raw_parts(header.payload.as_ptr(), header.payload.len()) };
    let (i, response_code) = be_u8(payload)?;
    match response_code {
        // OK
        0x00 => {
            let (_, response) = parse_response_ok(i)?;
            Ok((rem, response))
        }
        // ERR
        0xFF => {
            let (_, response) = parse_response_err(i)?;
            Ok((rem, response))
        }
        _ => parse_response_binary_resultset(rem, response_code as u64),
    }
}

pub fn parse_auth_request(i: &[u8]) -> IResult<&[u8], ()> {
    let (rem, _header) = parse_packet_header(i)?;
    Ok((rem, ()))
}

pub fn parse_auth_responsev2(i: &[u8]) -> IResult<&[u8], MysqlResponse> {
    let (rem, header) = parse_packet_header(i)?;
    let payload =
        unsafe { std::slice::from_raw_parts(header.payload.as_ptr(), header.payload.len()) };
    let (i, response_code) = be_u8(payload)?;
    match response_code {
        // OK
        0x00 => {
            let (_, response) = parse_response_ok(i)?;
            Ok((rem, response))
        }
        // auth data
        _ => Ok((
            rem,
            MysqlResponse {
                item: MysqlResponsePacket::AuthData,
            },
        )),
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_parse_handshake_request() {
        let pkt: &[u8] = &[
            0x49, 0x00, 0x00, 0x00, 0x0a, 0x38, 0x2e, 0x34, 0x2e, 0x30, 0x00, 0x51, 0x00, 0x00,
            0x00, 0x3e, 0x7d, 0x6a, 0x6a, 0x1a, 0x2d, 0x2b, 0x6b, 0x00, 0xff, 0xff, 0xff, 0x02,
            0x00, 0xff, 0xdf, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x61, 0x74, 0x54, 0x07, 0x62, 0x28, 0x5d, 0x21, 0x06, 0x44, 0x06, 0x62, 0x00, 0x63,
            0x61, 0x63, 0x68, 0x69, 0x6e, 0x67, 0x5f, 0x73, 0x68, 0x61, 0x32, 0x5f, 0x70, 0x61,
            0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x00,
        ];
        let (rem, handshake_request) = parse_handshake_request(pkt).unwrap();

        assert!(rem.is_empty());
        assert_eq!(handshake_request.protocol, 10);
        assert_eq!(handshake_request.version, "8.4.0");
        assert_eq!(handshake_request.conn_id, 81);
        assert_eq!(handshake_request.capability_flags1, 0xffff);
        assert_eq!(handshake_request.status_flags, 0x0002);
        assert_eq!(handshake_request.capability_flags2, 0xdfff);
        assert_eq!(handshake_request.auth_plugin_len, 21);
        assert_eq!(
            handshake_request.auth_plugin_data,
            Some("caching_sha2_password".to_string()),
        );
        let pkt: &[u8] = &[
            0x49, 0x00, 0x00, 0x00, 0x0a, 0x39, 0x2e, 0x30, 0x2e, 0x31, 0x00, 0x08, 0x00, 0x00,
            0x00, 0x5e, 0x09, 0x7c, 0x41, 0x76, 0x5d, 0x66, 0x17, 0x00, 0xff, 0xff, 0xff, 0x02,
            0x00, 0xff, 0xdf, 0x15, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x47, 0x4c, 0x7a, 0x03, 0x13, 0x35, 0x71, 0x0a, 0x4e, 0x2f, 0x45, 0x34, 0x00, 0x63,
            0x61, 0x63, 0x68, 0x69, 0x6e, 0x67, 0x5f, 0x73, 0x68, 0x61, 0x32, 0x5f, 0x70, 0x61,
            0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x00,
        ];
        let (rem, _) = parse_handshake_request(pkt).unwrap();

        assert!(rem.is_empty());
    }

    #[test]
    fn test_parse_handshake_response() {
        let pkt: &[u8] = &[
            0xc6, 0x00, 0x00, 0x01, 0x8d, 0xa2, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2d, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x72, 0x6f, 0x6f, 0x74, 0x00, 0x20,
            0xbd, 0xb9, 0xfd, 0xe3, 0x22, 0xce, 0x86, 0x7d, 0x6c, 0x1d, 0x0e, 0xad, 0x22, 0x92,
            0xde, 0x56, 0xe5, 0xf2, 0x3d, 0xf8, 0xe0, 0x1f, 0x6f, 0x59, 0x5e, 0x62, 0xa6, 0x6b,
            0x7e, 0x54, 0x61, 0xfc, 0x73, 0x65, 0x6e, 0x74, 0x69, 0x6e, 0x65, 0x6c, 0x2d, 0x66,
            0x6c, 0x6f, 0x77, 0x00, 0x63, 0x61, 0x63, 0x68, 0x69, 0x6e, 0x67, 0x5f, 0x73, 0x68,
            0x61, 0x32, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x00, 0x5b, 0x0c,
            0x5f, 0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x0f, 0x47,
            0x6f, 0x2d, 0x4d, 0x79, 0x53, 0x51, 0x4c, 0x2d, 0x44, 0x72, 0x69, 0x76, 0x65, 0x72,
            0x03, 0x5f, 0x6f, 0x73, 0x05, 0x6c, 0x69, 0x6e, 0x75, 0x78, 0x09, 0x5f, 0x70, 0x6c,
            0x61, 0x74, 0x66, 0x6f, 0x72, 0x6d, 0x05, 0x61, 0x6d, 0x64, 0x36, 0x34, 0x04, 0x5f,
            0x70, 0x69, 0x64, 0x06, 0x34, 0x35, 0x30, 0x39, 0x37, 0x36, 0x0c, 0x5f, 0x73, 0x65,
            0x72, 0x76, 0x65, 0x72, 0x5f, 0x68, 0x6f, 0x73, 0x74, 0x0a, 0x31, 0x37, 0x32, 0x2e,
            0x31, 0x37, 0x2e, 0x30, 0x2e, 0x32,
        ];

        let (rem, handshake_response) = parse_handshake_response(pkt).unwrap();

        assert!(rem.is_empty());
        assert_eq!(handshake_response.username, "root");
        assert_eq!(
            handshake_response.database,
            Some("sentinel-flow".to_string())
        );
        assert_eq!(
            handshake_response.client_plugin_name,
            Some("caching_sha2_password".to_string())
        );
        let pkt: &[u8] = &[
            0x5c, 0x00, 0x00, 0x01, 0x85, 0xa2, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2d, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x72, 0x6f, 0x6f, 0x74, 0x00, 0x20,
            0x9f, 0xbd, 0x98, 0xd7, 0x8f, 0x7b, 0x74, 0xfe, 0x9e, 0x4e, 0x99, 0x64, 0xc0, 0xd0,
            0x6a, 0x1d, 0x56, 0xbf, 0x36, 0xb1, 0xcd, 0x10, 0x6d, 0x3a, 0x37, 0xaf, 0x25, 0x22,
            0x06, 0xb6, 0xe5, 0x13, 0x63, 0x61, 0x63, 0x68, 0x69, 0x6e, 0x67, 0x5f, 0x73, 0x68,
            0x61, 0x32, 0x5f, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x00,
        ];
        let (rem, _) = parse_handshake_response(pkt).unwrap();

        assert!(rem.is_empty());
    }

    #[test]
    fn test_parse_query_request() {
        let pkt: &[u8] = &[
            0x12, 0x00, 0x00, 0x00, 0x03, 0x53, 0x45, 0x54, 0x20, 0x4e, 0x41, 0x4d, 0x45, 0x53,
            0x20, 0x75, 0x74, 0x66, 0x38, 0x6d, 0x62, 0x34,
        ];

        let (rem, request) = parse_request(pkt, None, None, None, 0).unwrap();

        assert!(rem.is_empty());
        assert_eq!(request.command_code, 0x03);

        let command = request.command;
        if let MysqlCommand::Query { query } = command {
            assert_eq!(query, "SET NAMES utf8mb4".to_string());
        } else {
            unreachable!();
        }
    }

    #[test]
    fn test_parse_ok_response() {
        let pkt: &[u8] = &[
            0x07, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00,
        ];

        let (rem, response) = parse_response(pkt).unwrap();
        assert!(rem.is_empty());

        let item = response.item;
        if let MysqlResponsePacket::Ok {
            rows,
            flags,
            warnings,
        } = item
        {
            assert_eq!(rows, 0);
            assert_eq!(flags, 0x0002);
            assert_eq!(warnings, 0);
        } else {
            unreachable!();
        }
    }

    #[test]
    fn test_parse_text_resultset_response() {
        let pkt: &[u8] = &[
            0x01, 0x00, 0x00, 0x01, 0x01, // Column count
            0x1f, 0x00, 0x00, 0x02, 0x03, 0x64, 0x65, 0x66, 0x00, 0x00, 0x00, 0x09, 0x56, 0x45,
            0x52, 0x53, 0x49, 0x4f, 0x4e, 0x28, 0x29, 0x00, 0x0c, 0xff, 0x00, 0x14, 0x00, 0x00,
            0x00, 0xfd, 0x01, 0x00, 0x1f, 0x00, 0x00, // Field packet
            0x05, 0x00, 0x00, 0x03, 0xfe, 0x00, 0x00, 0x02, 0x00, // EOF
            0x06, 0x00, 0x00, 0x04, 0x05, 0x39, 0x2e, 0x30, 0x2e, 0x31, // Row packet
            0x05, 0x00, 0x00, 0x05, 0xfe, 0x00, 0x00, 0x02, 0x00, // EOF
        ];

        let (rem, response) = parse_response(pkt).unwrap();
        assert!(rem.is_empty());

        let item = response.item;
        if let MysqlResponsePacket::ResultSet {
            n_cols,
            columns: _,
            eof: _,
            rows: _,
        } = item
        {
            assert_eq!(n_cols, 1);
        }
    }

    #[test]
    fn test_parse_quit_request() {
        let pkt: &[u8] = &[0x01, 0x00, 0x00, 0x00, 0x01];

        let (rem, request) = parse_request(pkt, None, None, None, 0).unwrap();

        assert!(rem.is_empty());
        assert_eq!(request.command_code, 0x01);

        let command = request.command;
        if let MysqlCommand::Quit = command {
        } else {
            unreachable!();
        }
    }

    #[test]
    fn test_parse_prepare_stmt_request() {
        let pkt: &[u8] = &[
            0x2b, 0x00, 0x00, 0x00, 0x16, 0x73, 0x65, 0x6c, 0x65, 0x63, 0x74, 0x20, 0x2a, 0x20,
            0x66, 0x72, 0x6f, 0x6d, 0x20, 0x72, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x73, 0x20,
            0x57, 0x48, 0x45, 0x52, 0x45, 0x20, 0x69, 0x64, 0x20, 0x3d, 0x3f, 0x20, 0x6c, 0x69,
            0x6d, 0x69, 0x74, 0x20, 0x31,
        ];

        let (rem, request) = parse_request(pkt, None, None, None, 0).unwrap();

        assert!(rem.is_empty());
        assert_eq!(request.command_code, 0x16);

        let command = request.command;

        if let MysqlCommand::StmtPrepare { query } = command {
            assert_eq!(query, "select * from requests WHERE id =? limit 1");
        } else {
            unreachable!();
        }
        let pkt: &[u8] = &[
            64, 0, 0, 0, 22, 83, 69, 76, 69, 67, 84, 32, 96, 114, 101, 115, 111, 117, 114, 99, 101,
            96, 32, 70, 82, 79, 77, 32, 96, 115, 121, 115, 95, 97, 117, 116, 104, 111, 114, 105,
            116, 105, 101, 115, 96, 32, 87, 72, 69, 82, 69, 32, 97, 117, 116, 104, 111, 114, 105,
            116, 121, 95, 105, 100, 32, 61, 32, 63,
        ];
        let (rem, request) = parse_request(pkt, None, None, None, 0).unwrap();

        assert!(rem.is_empty());
        assert_eq!(request.command_code, 0x16);
    }

    #[test]
    fn test_parse_close_stmt_request() {
        let pkt: &[u8] = &[0x05, 0x00, 0x00, 0x00, 0x19, 0x01, 0x00, 0x00, 0x00];

        let (rem, request) = parse_request(pkt, Some(1), None, None, 0).unwrap();

        assert!(rem.is_empty());
        assert_eq!(request.command_code, 0x19);

        let command = request.command;

        if let MysqlCommand::StmtClose { statement_id } = command {
            assert_eq!(statement_id, 1);
        } else {
            unreachable!();
        }
    }

    #[test]
    fn test_parse_ping_request() {
        let pkt: &[u8] = &[0x01, 0x00, 0x00, 0x00, 0x0e];
        let (rem, request) = parse_request(pkt, None, None, None, 0).unwrap();

        assert!(rem.is_empty());
        assert_eq!(request.command, MysqlCommand::Ping);
    }
}

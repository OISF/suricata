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
//
use std::collections::VecDeque;
use std::ffi::CString;

use nom7::IResult;

use crate::applayer::*;
use crate::conf::{conf_get, get_memval};
use crate::core::*;

use super::parser::*;

pub const MYSQL_CONFIG_DEFAULT_STREAM_DEPTH: u32 = 0;

static mut MYSQL_MAX_TX: usize = 1024;

pub static mut ALPROTO_MYSQL: AppProto = ALPROTO_UNKNOWN;

#[derive(FromPrimitive, Debug, AppLayerEvent)]
pub enum MysqlEvent {
    TooManyTransactions,
}

#[derive(Debug)]
pub struct MysqlTransaction {
    pub tx_id: u64,

    /// Required
    pub version: String,
    /// Optional when tls is true
    pub command: Option<String>,
    /// Optional when tls is true
    pub affected_rows: Option<u64>,
    /// Optional when tls is true
    pub rows: Option<Vec<String>>,
    pub tls: bool,

    pub complete: bool,
    pub tx_data: AppLayerTxData,
}

impl Transaction for MysqlTransaction {
    fn id(&self) -> u64 {
        self.tx_id
    }
}

impl MysqlTransaction {
    pub fn new(version: String) -> Self {
        Self {
            tx_id: 0,
            version,
            command: None,
            affected_rows: None,
            tls: false,
            tx_data: AppLayerTxData::new(),
            complete: false,
            rows: None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MysqlStateProgress {
    // Default State
    Init,

    // Connection Phase
    // Server send HandshakeRequest to Client
    // https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase.html
    Handshake,
    // Client send HandshakeResponse to Server
    // Server send AuthSwitchRequest to Client
    Auth,
    // Server send OkResponse to Client
    AuthFinished,

    // Command Phase
    // Client send QueryRequest to Server
    CommandReceived,
    // Server send EOF with 0x0A to Client
    TextResulsetContinue,
    // Server send QueryResponse to Client or Ok to Client
    CommandResponseReceived,
    // Server send LocalFileRequest with zero length to Client
    LocalFileRequestReceived,
    // Client send empty packet to Server
    LocalFileContentFinished,
    // Client send StatisticsRequest to Server
    StatisticsReceived,
    // Server send StatisticsResponse to client
    StatisticsResponseReceived,
    // Client send FieldList to Server
    FieldListReceived,
    // Server send FieldListResponse to client
    FieldListResponseReceived,
    // Client send ChangeUserRequest to Server
    ChangeUserReceived,
    // Server send OkResponse to client
    ChangeUserResponseReceived,
    // Client send Unknown to Server
    UnknownCommandReceived,
    // Client send StmtPrepareRequest to Server
    StmtPrepareReceived,
    // Server send StmtPrepareResponse to Client
    StmtPrepareResponseReceived,
    // Client send StmtExecRequest to Server
    StmtExecReceived,
    // Server send StmtExecResponse with EOF status equal 0x0a to Client
    StmtExecResponseContinue,
    // Server send ResultSetResponse to Client or Ok Response to Client
    StmtExecResponseReceived,
    // Client send StmtFetchRequest to Server
    StmtFetchReceived,
    // Server send StmtFetchResponse with EOF status equal 0x0a to Client
    StmtFetchResponseContinue,
    // Server send StmtFetchResponse to Client
    StmtFetchResponseReceived,
    // Client send StmtFetchRequest to Server
    StmtResetReceived,
    // Server send Ok or Err Response to Client
    StmtResetResponseReceived,
    // Client send StmtCloseRequest to Server
    StmtCloseReceived,

    // Client send QueryRequest and command equal Quit to Server
    // Client send ChangeUserRequest to server and server send ErrResponse to Client
    // Transport Layer EOF
    // Transport Layer Upgrade to TLS
    Finished,
}

#[derive(Debug)]
struct MysqlStatement {
    statement_id: Option<u32>,
    prepare_stmt: String,
    param_cnt: Option<u16>,
    param_types: Option<Vec<MysqlColumnDefinition>>,
    stmt_long_datas: Option<Vec<StmtLongData>>,
    rows: Option<Vec<MysqlResultBinarySetRow>>,
}

impl MysqlStatement {
    fn new(prepare_stmt: String) -> Self {
        MysqlStatement {
            statement_id: None,
            prepare_stmt,
            param_cnt: None,
            param_types: None,
            stmt_long_datas: None,
            rows: None,
        }
    }

    fn set_statement_id(&mut self, statement_id: u32) {
        self.statement_id = Some(statement_id);
    }

    fn set_param_cnt(&mut self, param_cnt: u16) {
        self.param_cnt = Some(param_cnt);
    }

    fn set_param_types(&mut self, cols: Vec<MysqlColumnDefinition>) {
        self.param_types = Some(cols);
    }

    fn add_stmt_long_datas(&mut self, long_data: StmtLongData) {
        if let Some(stmt_long_datas) = &mut self.stmt_long_datas {
            stmt_long_datas.push(long_data);
        } else {
            self.stmt_long_datas = Some(vec![long_data]);
        }
    }

    fn reset_stmt_long_datas(&mut self) {
        self.stmt_long_datas.take();
    }

    fn add_rows(&mut self, rows: Vec<MysqlResultBinarySetRow>) {
        if let Some(old_rows) = &mut self.rows {
            old_rows.extend(rows);
        } else {
            self.rows = Some(rows);
        }
    }

    fn execute(&self, params: Vec<String>) -> Option<String> {
        let prepare_stmt = self.prepare_stmt.clone();
        let mut query = String::new();
        if !params.is_empty()
            && self.param_cnt.is_some()
            && self.param_cnt.unwrap() as usize == params.len()
        {
            let mut params = params.iter();
            for part in prepare_stmt.split('?') {
                query.push_str(part);
                if let Some(param) = params.next() {
                    query.push_str(param);
                }
            }
            Some(query)
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub struct MysqlState {
    pub state_data: AppLayerStateData,
    pub tx_id: u64,
    transactions: VecDeque<MysqlTransaction>,
    request_gap: bool,
    response_gap: bool,
    state_progress: MysqlStateProgress,
    tx_index_completed: usize,

    client_flags: u32,
    version: Option<String>,
    tls: bool,
    /// stmt prepare
    prepare_stmt: Option<MysqlStatement>,
}

impl State<MysqlTransaction> for MysqlState {
    fn get_transaction_count(&self) -> usize {
        self.transactions.len()
    }

    fn get_transaction_by_index(&self, index: usize) -> Option<&MysqlTransaction> {
        self.transactions.get(index)
    }
}

impl Default for MysqlState {
    fn default() -> Self {
        Self::new()
    }
}

impl MysqlState {
    pub fn new() -> Self {
        let state = Self {
            state_data: AppLayerStateData::new(),
            tx_id: 0,
            transactions: VecDeque::new(),
            request_gap: false,
            response_gap: false,
            state_progress: MysqlStateProgress::Init,
            tx_index_completed: 0,

            client_flags: 0,
            version: None,
            tls: false,
            prepare_stmt: None,
        };
        state
    }

    pub fn free_tx(&mut self, tx_id: u64) {
        let len = self.transactions.len();
        let mut found = false;
        let mut index = 0;
        for i in 0..len {
            let tx = &self.transactions[i];
            if tx.tx_id == tx_id + 1 {
                found = true;
                index = i;
                break;
            }
        }
        if found {
            self.tx_index_completed = 0;
            self.transactions.remove(index);
        }
    }

    pub fn get_tx(&mut self, tx_id: u64) -> Option<&MysqlTransaction> {
        self.transactions.iter().find(|tx| tx.tx_id == tx_id + 1)
    }

    fn get_tx_mut(&mut self, tx_id: u64) -> Option<&mut MysqlTransaction> {
        self.transactions
            .iter_mut()
            .find(|tx| tx.tx_id == tx_id + 1)
    }

    fn set_event(tx: &mut MysqlTransaction, event: MysqlEvent) {
        tx.tx_data.set_event(event as u8);
    }

    fn new_tx(&mut self, command: String) -> MysqlTransaction {
        let mut tx = MysqlTransaction::new(self.version.clone().unwrap_or_default());
        self.tx_id += 1;
        tx.tx_id = self.tx_id;
        tx.tls = self.tls;
        if tx.tls {
            tx.complete = true;
        }
        tx.command = Some(command);
        SCLogDebug!("Creating new transaction.tx_id: {}", tx.tx_id);
        if self.transactions.len() > unsafe { MYSQL_MAX_TX } + self.tx_index_completed {
            let mut index = self.tx_index_completed;
            for tx_old in &mut self.transactions.range_mut(self.tx_index_completed..) {
                index += 1;
                if !tx_old.complete {
                    tx_old.complete = true;
                    MysqlState::set_event(tx_old, MysqlEvent::TooManyTransactions);
                    break;
                }
            }
            self.tx_index_completed = index;
        }
        tx
    }

    /// Find or create a new transaction
    ///
    /// If a new transaction is created, push that into state.transactions before returning &mut to last tx
    /// If we can't find a transaction and we should not create one, we return None
    /// The moment when this is called will may impact the logic of transaction tracking (e.g. when a tx is considered completed)
    fn create_tx(&mut self, command: String) -> Option<&mut MysqlTransaction> {
        let tx = self.new_tx(command);
        SCLogDebug!("create state is {:?}", &self.state_progress);
        self.transactions.push_back(tx);
        self.transactions.back_mut()
    }

    fn request_next_state(
        &mut self, request: MysqlFEMessage, f: *const Flow,
    ) -> Option<MysqlStateProgress> {
        match request {
            MysqlFEMessage::HandshakeResponse(resp) => {
                // for now, don't support compress
                if resp.zstd_compression_level.is_some() {
                    return Some(MysqlStateProgress::Finished);
                }
                if resp.client_flags & CLIENT_DEPRECATE_EOF != 0
                    || resp.client_flags & CLIENT_OPTIONAL_RESULTSET_METADATA != 0
                {
                    return Some(MysqlStateProgress::Finished);
                }
                self.client_flags = resp.client_flags;
                Some(MysqlStateProgress::Auth)
            }
            MysqlFEMessage::SSLRequest(_) => {
                unsafe {
                    AppLayerRequestProtocolTLSUpgrade(f);
                }
                self.tls = true;
                self.create_tx("".to_string());
                Some(MysqlStateProgress::Finished)
            }
            MysqlFEMessage::AuthRequest => None,
            MysqlFEMessage::LocalFileData(length) => {
                if length == 0 {
                    let tx = self.get_tx_mut(self.tx_id - 1);
                    if let Some(tx) = tx {
                        tx.complete = true;
                    }
                    return Some(MysqlStateProgress::LocalFileContentFinished);
                }
                None
            }
            MysqlFEMessage::Request(req) => match req.command {
                MysqlCommand::Query { query: _ } => {
                    self.create_tx(req.command.to_string());
                    return Some(MysqlStateProgress::CommandReceived);
                }
                MysqlCommand::StmtPrepare { query } => {
                    self.prepare_stmt = Some(MysqlStatement::new(query));
                    return Some(MysqlStateProgress::StmtPrepareReceived);
                }

                MysqlCommand::StmtExecute {
                    statement_id: expected_statement_id,
                    params,
                } => {
                    if let Some(prepare_stmt) = &self.prepare_stmt {
                        if let Some(statement_id) = prepare_stmt.statement_id {
                            if statement_id == expected_statement_id {
                                let command = prepare_stmt.execute(params.unwrap_or_default());
                                self.create_tx(command.unwrap_or_default());
                            } else {
                                SCLogWarning!(
                                    "Receive stmt exec statement_id {} not equal we need {}",
                                    expected_statement_id,
                                    statement_id
                                );
                                return Some(MysqlStateProgress::Finished);
                            }
                        }
                    } else {
                        return Some(MysqlStateProgress::Finished);
                    }
                    return Some(MysqlStateProgress::StmtExecReceived);
                }
                MysqlCommand::StmtFetch {
                    statement_id: _,
                    number_rows: _,
                } => {
                    return Some(MysqlStateProgress::StmtFetchReceived);
                }
                MysqlCommand::StmtSendLongData(stmt_long_data) => {
                    if let Some(prepare_stmt) = &mut self.prepare_stmt {
                        if let Some(statement_id) = prepare_stmt.statement_id {
                            if statement_id == stmt_long_data.statement_id {
                                prepare_stmt.add_stmt_long_datas(stmt_long_data);
                            }
                        }
                    }
                    None
                }
                MysqlCommand::StmtReset { statement_id } => {
                    if let Some(prepare_stmt) = &mut self.prepare_stmt {
                        if let Some(expected_statement_id) = prepare_stmt.statement_id {
                            if statement_id == expected_statement_id {
                                prepare_stmt.reset_stmt_long_datas();
                            }
                        }
                    }
                    return Some(MysqlStateProgress::StmtResetReceived);
                }
                MysqlCommand::StmtClose { statement_id } => {
                    if let Some(prepare_stmt) = &self.prepare_stmt {
                        if let Some(expected_statement_id) = prepare_stmt.statement_id {
                            if statement_id == expected_statement_id {
                                self.prepare_stmt.take();
                            } else {
                                SCLogWarning!(
                                    "Receive stmt close statement_id {} not equal we need {}",
                                    expected_statement_id,
                                    statement_id
                                );
                            }
                        } else {
                            SCLogWarning!("Receive stmt close without stmt prepare response");
                        }
                    } else {
                        SCLogWarning!("Receive stmt close without stmt prepare response");
                    }

                    return Some(MysqlStateProgress::StmtCloseReceived);
                }
                MysqlCommand::Quit => {
                    self.create_tx(req.command.to_string());
                    return Some(MysqlStateProgress::Finished);
                }
                MysqlCommand::Ping
                | MysqlCommand::Debug
                | MysqlCommand::ResetConnection
                | MysqlCommand::SetOption => {
                    self.create_tx(req.command.to_string());
                    Some(MysqlStateProgress::CommandReceived)
                }
                MysqlCommand::Statistics => Some(MysqlStateProgress::StatisticsReceived),
                MysqlCommand::FieldList { table: _ } => {
                    self.create_tx(req.command.to_string());
                    return Some(MysqlStateProgress::FieldListReceived);
                }
                MysqlCommand::ChangeUser => {
                    self.create_tx(req.command.to_string());
                    return Some(MysqlStateProgress::ChangeUserReceived);
                }
                _ => {
                    SCLogWarning!("Unknown command {}", req.command_code);
                    return Some(MysqlStateProgress::UnknownCommandReceived);
                }
            },
        }
    }

    fn state_based_req_parsing(
        state: MysqlStateProgress, i: &[u8], param_cnt: Option<u16>,
        param_types: Option<Vec<MysqlColumnDefinition>>,
        stmt_long_datas: Option<Vec<StmtLongData>>, client_flags: u32,
    ) -> IResult<&[u8], MysqlFEMessage> {
        match state {
            MysqlStateProgress::Handshake => {
                let old = i;
                let (_, client_flags) = parse_handshake_capabilities(i)?;
                if client_flags & CLIENT_SSL != 0 {
                    let (i, req) = parse_handshake_ssl_request(old)?;
                    return Ok((i, MysqlFEMessage::SSLRequest(req)));
                }
                let (i, req) = parse_handshake_response(old)?;
                Ok((i, MysqlFEMessage::HandshakeResponse(req)))
            }
            MysqlStateProgress::Auth => {
                let (i, _) = parse_auth_request(i)?;
                Ok((i, MysqlFEMessage::AuthRequest))
            }
            MysqlStateProgress::LocalFileRequestReceived => {
                let (i, length) = parse_local_file_data_content(i)?;
                Ok((i, MysqlFEMessage::LocalFileData(length)))
            }
            _ => {
                let (i, req) =
                    parse_request(i, param_cnt, param_types, stmt_long_datas, client_flags)?;
                Ok((i, MysqlFEMessage::Request(req)))
            }
        }
    }

    pub fn parse_request(&mut self, flow: *const Flow, i: &[u8]) -> AppLayerResult {
        // We're not interested in empty requests.
        if i.is_empty() {
            return AppLayerResult::ok();
        }

        // If there was gap, check we can sync up again.
        if self.request_gap {
            if probe(i).is_err() {
                SCLogDebug!("Suricata interprets there's a gap in the request");
                return AppLayerResult::ok();
            }

            // It looks like we're in sync with the message header
            // clear gap state and keep parsing.
            self.request_gap = false;
        }
        if self.state_progress == MysqlStateProgress::Finished {
            return AppLayerResult::ok();
        }

        let mut start = i;
        while !start.is_empty() {
            SCLogDebug!(
                "In 'parse_request' State Progress is: {:?}",
                &self.state_progress
            );
            let mut stmt_long_datas = None;
            let mut param_cnt = None;
            let mut param_types = None;
            if let Some(prepare_stmt) = &self.prepare_stmt {
                stmt_long_datas = prepare_stmt.stmt_long_datas.clone();
                param_cnt = prepare_stmt.param_cnt;
                param_types = prepare_stmt.param_types.clone();
            }

            match MysqlState::state_based_req_parsing(
                self.state_progress,
                start,
                param_cnt,
                param_types.clone(),
                stmt_long_datas,
                self.client_flags,
            ) {
                Ok((rem, request)) => {
                    SCLogDebug!("Request is {:?}", &request);
                    start = rem;
                    if let Some(state) = self.request_next_state(request, flow) {
                        self.state_progress = state;
                    }
                }
                Err(nom7::Err::Incomplete(_needed)) => {
                    let consumed = i.len() - start.len();
                    let needed_estimation = start.len() + 1;
                    SCLogDebug!(
                        "Needed: {:?}, estimated needed: {:?}",
                        _needed,
                        needed_estimation
                    );
                    return AppLayerResult::incomplete(consumed as u32, needed_estimation as u32);
                }
                Err(err) => {
                    SCLogError!(
                        "Error while parsing MySQL request, state: {:?} err: {:?}",
                        self.state_progress,
                        err
                    );
                    return AppLayerResult::err();
                }
            }
        }

        // All Input was fully consumed.
        AppLayerResult::ok()
    }

    /// When the state changes based on a specific response, there are other actions we may need to perform
    ///
    /// If there is data from the backend message that Suri should store separately in the State or
    /// Transaction, that is also done here
    fn response_next_state(&mut self, response: MysqlBEMessage) -> Option<MysqlStateProgress> {
        match response {
            MysqlBEMessage::HandshakeRequest(req) => {
                self.version = Some(req.version.clone());
                Some(MysqlStateProgress::Handshake)
            }

            MysqlBEMessage::Response(resp) => match resp.item {
                MysqlResponsePacket::LocalInFileRequest => {
                    Some(MysqlStateProgress::LocalFileRequestReceived)
                }
                MysqlResponsePacket::FieldsList { columns: _ } => {
                    let tx = if self.tx_id > 0 {
                        self.get_tx_mut(self.tx_id - 1)
                    } else {
                        None
                    };
                    if let Some(tx) = tx {
                        tx.complete = true;
                    }
                    Some(MysqlStateProgress::FieldListResponseReceived)
                }
                MysqlResponsePacket::Statistics => {
                    let tx = if self.tx_id > 0 {
                        self.get_tx_mut(self.tx_id - 1)
                    } else {
                        None
                    };
                    if let Some(tx) = tx {
                        tx.complete = true;
                    }
                    Some(MysqlStateProgress::StatisticsResponseReceived)
                }
                MysqlResponsePacket::AuthSwithRequest => Some(MysqlStateProgress::Auth),
                MysqlResponsePacket::AuthData => None,
                MysqlResponsePacket::Err { .. } => match self.state_progress {
                    MysqlStateProgress::CommandReceived
                    | MysqlStateProgress::TextResulsetContinue => {
                        let tx = if self.tx_id > 0 {
                            self.get_tx_mut(self.tx_id - 1)
                        } else {
                            None
                        };
                        if let Some(tx) = tx {
                            tx.complete = true;
                        }
                        Some(MysqlStateProgress::CommandResponseReceived)
                    }
                    MysqlStateProgress::FieldListReceived => {
                        let tx = if self.tx_id > 0 {
                            self.get_tx_mut(self.tx_id - 1)
                        } else {
                            None
                        };
                        if let Some(tx) = tx {
                            tx.complete = true;
                        }
                        Some(MysqlStateProgress::FieldListResponseReceived)
                    }
                    MysqlStateProgress::StmtExecReceived
                    | MysqlStateProgress::StmtExecResponseContinue => {
                        let tx = if self.tx_id > 0 {
                            self.get_tx_mut(self.tx_id - 1)
                        } else {
                            None
                        };
                        if let Some(tx) = tx {
                            tx.complete = true;
                        }
                        Some(MysqlStateProgress::StmtExecResponseReceived)
                    }
                    MysqlStateProgress::StmtResetReceived => {
                        Some(MysqlStateProgress::StmtResetResponseReceived)
                    }
                    MysqlStateProgress::ChangeUserReceived => {
                        let tx = if self.tx_id > 0 {
                            self.get_tx_mut(self.tx_id - 1)
                        } else {
                            None
                        };
                        if let Some(tx) = tx {
                            tx.complete = true;
                        }
                        Some(MysqlStateProgress::Finished)
                    }
                    MysqlStateProgress::StmtFetchReceived
                    | MysqlStateProgress::StmtFetchResponseContinue => {
                        let tx = if self.tx_id > 0 {
                            self.get_tx_mut(self.tx_id - 1)
                        } else {
                            None
                        };
                        if let Some(tx) = tx {
                            tx.complete = true;
                        }
                        Some(MysqlStateProgress::StmtFetchResponseReceived)
                    }
                    _ => None,
                },
                MysqlResponsePacket::Ok {
                    rows,
                    flags: _,
                    warnings: _,
                } => match self.state_progress {
                    MysqlStateProgress::Auth => Some(MysqlStateProgress::AuthFinished),
                    MysqlStateProgress::CommandReceived => {
                        let tx = if self.tx_id > 0 {
                            self.get_tx_mut(self.tx_id - 1)
                        } else {
                            None
                        };
                        if let Some(tx) = tx {
                            tx.affected_rows = Some(rows);
                            tx.complete = true;
                        }
                        Some(MysqlStateProgress::CommandResponseReceived)
                    }
                    MysqlStateProgress::StmtExecReceived => {
                        let tx = if self.tx_id > 0 {
                            self.get_tx_mut(self.tx_id - 1)
                        } else {
                            None
                        };
                        if let Some(tx) = tx {
                            tx.affected_rows = Some(rows);
                            tx.complete = true;
                        }
                        Some(MysqlStateProgress::StmtExecResponseReceived)
                    }
                    MysqlStateProgress::ChangeUserReceived => {
                        Some(MysqlStateProgress::ChangeUserResponseReceived)
                    }
                    MysqlStateProgress::StmtResetReceived => {
                        Some(MysqlStateProgress::StmtResetResponseReceived)
                    }
                    MysqlStateProgress::TextResulsetContinue => {
                        let tx = if self.tx_id > 0 {
                            self.get_tx_mut(self.tx_id - 1)
                        } else {
                            None
                        };
                        if let Some(tx) = tx {
                            tx.complete = true;
                        }
                        Some(MysqlStateProgress::CommandResponseReceived)
                    }
                    MysqlStateProgress::StmtExecResponseContinue => {
                        let prepare_stmt = self.prepare_stmt.take();
                        if self.tx_id > 0 {
                            let tx = self.get_tx_mut(self.tx_id - 1);
                            if let Some(tx) = tx {
                                if let Some(mut prepare_stmt) = prepare_stmt {
                                    let rows = prepare_stmt.rows.take();
                                    if let Some(rows) = rows {
                                        tx.rows = Some(
                                            rows.into_iter()
                                                .map(|row| match row {
                                                    MysqlResultBinarySetRow::Err => String::new(),
                                                    MysqlResultBinarySetRow::Text(text) => text,
                                                })
                                                .collect::<Vec<String>>(),
                                        );
                                    }

                                    tx.complete = true;
                                }
                            }
                        }
                        Some(MysqlStateProgress::StmtExecResponseReceived)
                    }
                    MysqlStateProgress::StmtFetchResponseContinue => {
                        Some(MysqlStateProgress::StmtFetchResponseReceived)
                    }
                    _ => None,
                },
                MysqlResponsePacket::ResultSet {
                    n_cols: _,
                    columns: _,
                    eof,
                    rows,
                } => {
                    let tx = if self.tx_id > 0 {
                        self.get_tx_mut(self.tx_id - 1)
                    } else {
                        None
                    };
                    if !rows.is_empty() {
                        let mut rows = rows.into_iter().map(|row| row.texts.join(",")).collect();
                        if let Some(tx) = tx {
                            if eof.status_flags != 0x0A {
                                tx.rows = Some(rows);
                                Some(MysqlStateProgress::CommandResponseReceived)
                            } else {
                                // MultiStatement
                                if let Some(state_rows) = tx.rows.as_mut() {
                                    state_rows.append(&mut rows);
                                } else {
                                    tx.rows = Some(rows);
                                }

                                Some(MysqlStateProgress::TextResulsetContinue)
                            }
                        } else {
                            Some(MysqlStateProgress::Finished)
                        }
                    } else {
                        Some(MysqlStateProgress::CommandResponseReceived)
                    }
                }
                MysqlResponsePacket::StmtPrepare {
                    statement_id,
                    num_params,
                    params,
                    ..
                } => {
                    if let Some(prepare_stmt) = &mut self.prepare_stmt {
                        prepare_stmt.set_statement_id(statement_id);
                        prepare_stmt.set_param_cnt(num_params);
                        if let Some(params) = params {
                            prepare_stmt.set_param_types(params);
                        }
                    }

                    Some(MysqlStateProgress::StmtPrepareResponseReceived)
                }
                MysqlResponsePacket::StmtFetch => {
                    Some(MysqlStateProgress::StmtFetchResponseReceived)
                }
                MysqlResponsePacket::BinaryResultSet {
                    n_cols: _,
                    eof,
                    rows,
                } => {
                    if self.state_progress == MysqlStateProgress::StmtFetchReceived
                        || self.state_progress == MysqlStateProgress::StmtFetchResponseContinue
                    {
                        return Some(MysqlStateProgress::StmtFetchResponseContinue);
                    }

                    if !rows.is_empty() {
                        if eof.status_flags != 0x0A {
                            let tx = if self.tx_id > 0 {
                                self.get_tx_mut(self.tx_id - 1)
                            } else {
                                None
                            };
                            if let Some(tx) = tx {
                                tx.rows = Some(
                                    rows.into_iter()
                                        .map(|row| match row {
                                            MysqlResultBinarySetRow::Err => String::new(),
                                            MysqlResultBinarySetRow::Text(text) => text,
                                        })
                                        .collect::<Vec<String>>(),
                                );
                                tx.complete = true;
                            }

                            Some(MysqlStateProgress::StmtExecResponseReceived)
                        } else {
                            // MultiResulset
                            if let Some(prepare_stmt) = &mut self.prepare_stmt {
                                prepare_stmt.add_rows(rows);
                            }

                            Some(MysqlStateProgress::StmtExecResponseContinue)
                        }
                    } else {
                        Some(MysqlStateProgress::StmtExecResponseReceived)
                    }
                }
                _ => None,
            },
        }
    }

    fn state_based_resp_parsing(
        state: MysqlStateProgress, i: &[u8], client_flags: u32,
    ) -> IResult<&[u8], MysqlBEMessage> {
        match state {
            MysqlStateProgress::Init => {
                let (i, resp) = parse_handshake_request(i)?;
                Ok((i, MysqlBEMessage::HandshakeRequest(resp)))
            }

            MysqlStateProgress::Auth => {
                let (i, resp) = parse_auth_responsev2(i)?;
                Ok((i, MysqlBEMessage::Response(resp)))
            }

            MysqlStateProgress::StmtPrepareReceived => {
                let (i, resp) = parse_stmt_prepare_response(i, client_flags)?;
                Ok((i, MysqlBEMessage::Response(resp)))
            }

            MysqlStateProgress::StmtExecReceived | MysqlStateProgress::StmtExecResponseContinue => {
                let (i, resp) = parse_stmt_execute_response(i)?;
                Ok((i, MysqlBEMessage::Response(resp)))
            }

            MysqlStateProgress::StmtFetchReceived
            | MysqlStateProgress::StmtFetchResponseContinue => {
                let (i, resp) = parse_stmt_fetch_response(i)?;
                Ok((i, MysqlBEMessage::Response(resp)))
            }

            MysqlStateProgress::FieldListReceived => {
                let (i, resp) = parse_field_list_response(i)?;
                Ok((i, MysqlBEMessage::Response(resp)))
            }
            MysqlStateProgress::StatisticsReceived => {
                let (i, resp) = parse_statistics_response(i)?;
                Ok((i, MysqlBEMessage::Response(resp)))
            }
            MysqlStateProgress::ChangeUserReceived => {
                let (i, resp) = parse_change_user_response(i)?;
                Ok((i, MysqlBEMessage::Response(resp)))
            }

            _ => {
                let (i, resp) = parse_response(i)?;
                Ok((i, MysqlBEMessage::Response(resp)))
            }
        }
    }

    fn invalid_state_resp(&self) -> bool {
        use MysqlStateProgress::*;
        self.state_progress == CommandResponseReceived
            || self.state_progress == StmtCloseReceived
            || self.state_progress == StmtPrepareResponseReceived
            || self.state_progress == StmtExecResponseReceived
    }

    pub fn parse_response(&mut self, i: &[u8]) -> AppLayerResult {
        // We're not interested in empty responses.
        if i.is_empty() {
            return AppLayerResult::ok();
        }

        if self.response_gap {
            if probe(i).is_err() {
                SCLogDebug!("Suricata interprets there's a gap in the response");
                return AppLayerResult::ok();
            }

            // It seems we're in sync with a message header, clear gap state and keep parsing.
            self.response_gap = false;
        }

        let mut start = i;

        while !start.is_empty() {
            if self.state_progress == MysqlStateProgress::Finished || self.invalid_state_resp() {
                return AppLayerResult::ok();
            }
            match MysqlState::state_based_resp_parsing(
                self.state_progress,
                start,
                self.client_flags,
            ) {
                Ok((rem, response)) => {
                    start = rem;

                    SCLogDebug!("Response is {:?}", &response);
                    if let Some(state) = self.response_next_state(response) {
                        self.state_progress = state;
                    }
                }
                Err(nom7::Err::Incomplete(_needed)) => {
                    let consumed = i.len() - start.len();
                    let needed_estimation = start.len() + 1;
                    SCLogDebug!(
                        "Needed: {:?}, estimated needed: {:?}, start is {:?}",
                        _needed,
                        needed_estimation,
                        &start
                    );
                    return AppLayerResult::incomplete(consumed as u32, needed_estimation as u32);
                }
                Err(_err) => {
                    SCLogDebug!(
                        "Error while parsing MySQL response, state: {:?} err: {:?}",
                        self.state_progress,
                        _err,
                    );
                    return AppLayerResult::err();
                }
            }
        }

        // All Input was fully consumed.
        AppLayerResult::ok()
    }

    pub fn on_request_gap(&mut self, _size: u32) {
        self.request_gap = true;
    }

    pub fn on_response_gap(&mut self, _size: u32) {
        self.response_gap = true;
    }
}

/// Probe for a valid mysql message
fn probe(i: &[u8]) -> IResult<&[u8], ()> {
    let (i, _) = parse_packet_header(i)?;
    Ok((i, ()))
}

// C exports

/// C entry point for a probing parser.
#[no_mangle]
pub unsafe extern "C" fn rs_mysql_probing_ts(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    if input_len >= 1 && !input.is_null() {
        let slice: &[u8] = build_slice!(input, input_len as usize);
        match parse_handshake_response(slice) {
            Ok(_) => return ALPROTO_MYSQL,
            Err(nom7::Err::Incomplete(_)) => return ALPROTO_UNKNOWN,
            Err(_err) => {
                SCLogDebug!("failed to probe request {:?}", _err);
                return ALPROTO_FAILED;
            }
        }
    }

    return ALPROTO_UNKNOWN;
}

#[no_mangle]
pub unsafe extern "C" fn rs_mysql_probing_tc(
    _flow: *const Flow, _direction: u8, input: *const u8, input_len: u32, _rdir: *mut u8,
) -> AppProto {
    if input_len >= 1 && !input.is_null() {
        let slice: &[u8] = build_slice!(input, input_len as usize);
        match parse_handshake_request(slice) {
            Ok(_) => return ALPROTO_MYSQL,
            Err(nom7::Err::Incomplete(_)) => return ALPROTO_UNKNOWN,
            Err(_err) => {
                SCLogDebug!("failed to probe response {:?}", _err);
                return ALPROTO_FAILED;
            }
        }
    }

    return ALPROTO_UNKNOWN;
}

#[no_mangle]
pub extern "C" fn rs_mysql_state_new(
    _orig_state: *mut std::os::raw::c_void, _orig_proto: AppProto,
) -> *mut std::os::raw::c_void {
    let state = MysqlState::new();
    let boxed = Box::new(state);
    return Box::into_raw(boxed) as *mut _;
}

#[no_mangle]
pub extern "C" fn rs_mysql_state_free(state: *mut std::os::raw::c_void) {
    std::mem::drop(unsafe { Box::from_raw(state as *mut MysqlState) });
}

#[no_mangle]
pub extern "C" fn rs_mysql_state_tx_free(state: *mut std::os::raw::c_void, tx_id: u64) {
    let state_safe: &mut MysqlState;
    unsafe {
        state_safe = cast_pointer!(state, MysqlState);
    }
    state_safe.free_tx(tx_id);
}

#[no_mangle]
pub unsafe extern "C" fn rs_mysql_parse_request(
    flow: *const Flow, state: *mut std::os::raw::c_void, pstate: *mut std::os::raw::c_void,
    stream_slice: StreamSlice, _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    if stream_slice.is_empty() {
        if AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TS) > 0 {
            SCLogDebug!(" Caracal reached `eof`");
            return AppLayerResult::ok();
        } else {
            return AppLayerResult::err();
        }
    }

    let state_safe: &mut MysqlState = cast_pointer!(state, MysqlState);

    if stream_slice.is_gap() {
        state_safe.on_request_gap(stream_slice.gap_size());
    } else {
        return state_safe.parse_request(flow, stream_slice.as_slice());
    }
    AppLayerResult::ok()
}

#[no_mangle]
pub unsafe extern "C" fn rs_mysql_parse_response(
    _flow: *const Flow, state: *mut std::os::raw::c_void, pstate: *mut std::os::raw::c_void,
    stream_slice: StreamSlice, _data: *const std::os::raw::c_void,
) -> AppLayerResult {
    if stream_slice.is_empty() {
        if AppLayerParserStateIssetFlag(pstate, APP_LAYER_PARSER_EOF_TC) > 0 {
            return AppLayerResult::ok();
        } else {
            return AppLayerResult::err();
        }
    }

    let state_safe: &mut MysqlState = cast_pointer!(state, MysqlState);

    if stream_slice.is_gap() {
        state_safe.on_response_gap(stream_slice.gap_size());
    } else {
        return state_safe.parse_response(stream_slice.as_slice());
    }
    AppLayerResult::ok()
}

#[no_mangle]
pub extern "C" fn rs_mysql_state_get_tx_count(state: *mut std::os::raw::c_void) -> u64 {
    let state_safe: &mut MysqlState;
    unsafe {
        state_safe = cast_pointer!(state, MysqlState);
    }
    return state_safe.tx_id;
}

#[no_mangle]
pub unsafe extern "C" fn rs_mysql_state_get_tx(
    state: *mut std::os::raw::c_void, tx_id: u64,
) -> *mut std::os::raw::c_void {
    let state_safe: &mut MysqlState = cast_pointer!(state, MysqlState);
    match state_safe.get_tx(tx_id) {
        Some(tx) => {
            return tx as *const _ as *mut _;
        }
        None => {
            return std::ptr::null_mut();
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_mysql_tx_get_alstate_progress(
    tx: *mut std::os::raw::c_void, _direction: u8,
) -> std::os::raw::c_int {
    let tx = cast_pointer!(tx, MysqlTransaction);
    if tx.complete {
        return 1;
    }
    return 0;
}

export_tx_data_get!(rs_mysql_get_tx_data, MysqlTransaction);
export_state_data_get!(rs_mysql_get_state_data, MysqlState);

// Parser name as a C style string.
const PARSER_NAME: &[u8] = b"mysql\0";

#[no_mangle]
pub unsafe extern "C" fn rs_mysql_register_parser() {
    let default_port = CString::new("[3306]").unwrap();
    let mut stream_depth = MYSQL_CONFIG_DEFAULT_STREAM_DEPTH;
    let parser = RustParser {
        name: PARSER_NAME.as_ptr() as *const std::os::raw::c_char,
        default_port: default_port.as_ptr(),
        ipproto: IPPROTO_TCP,
        probe_ts: Some(rs_mysql_probing_ts),
        probe_tc: Some(rs_mysql_probing_tc),
        min_depth: 0,
        max_depth: 16,
        state_new: rs_mysql_state_new,
        state_free: rs_mysql_state_free,
        tx_free: rs_mysql_state_tx_free,
        parse_ts: rs_mysql_parse_request,
        parse_tc: rs_mysql_parse_response,
        get_tx_count: rs_mysql_state_get_tx_count,
        get_tx: rs_mysql_state_get_tx,
        tx_comp_st_ts: 1,
        tx_comp_st_tc: 1,
        tx_get_progress: rs_mysql_tx_get_alstate_progress,
        get_eventinfo: Some(MysqlEvent::get_event_info),
        get_eventinfo_byid: Some(MysqlEvent::get_event_info_by_id),
        localstorage_new: None,
        localstorage_free: None,
        get_tx_files: None,
        get_tx_iterator: Some(
            crate::applayer::state_get_tx_iterator::<MysqlState, MysqlTransaction>,
        ),
        get_tx_data: rs_mysql_get_tx_data,
        get_state_data: rs_mysql_get_state_data,
        apply_tx_config: None,
        flags: APP_LAYER_PARSER_OPT_ACCEPT_GAPS,
        get_frame_id_by_name: None,
        get_frame_name_by_id: None,
    };

    let ip_proto_str = CString::new("tcp").unwrap();

    if AppLayerProtoDetectConfProtoDetectionEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
        let alproto = AppLayerRegisterProtocolDetection(&parser, 1);
        ALPROTO_MYSQL = alproto;
        if AppLayerParserConfParserEnabled(ip_proto_str.as_ptr(), parser.name) != 0 {
            let _ = AppLayerRegisterParser(&parser, alproto);
        }
        SCLogDebug!("Rust mysql parser registered.");
        let retval = conf_get("app-layer.protocols.mysql.stream-depth");
        if let Some(val) = retval {
            match get_memval(val) {
                Ok(retval) => {
                    stream_depth = retval as u32;
                }
                Err(_) => {
                    SCLogError!("Invalid depth value");
                }
            }
            AppLayerParserSetStreamDepth(IPPROTO_TCP, ALPROTO_MYSQL, stream_depth)
        }
        if let Some(val) = conf_get("app-layer.protocols.mysql.max-tx") {
            if let Ok(v) = val.parse::<usize>() {
                MYSQL_MAX_TX = v;
            } else {
                SCLogError!("Invalid value for mysql.max-tx");
            }
        }
        AppLayerParserRegisterLogger(IPPROTO_TCP, ALPROTO_MYSQL);
    } else {
        SCLogDebug!("Protocol detector and parser disabled for MYSQL.");
    }
}

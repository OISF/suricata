/* Copyright (C) 2019 Open Information Security Foundation
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

// written by Giuseppe Longo <giuseppe@glongo.it>

use crate::jsonbuilder::{JsonBuilder, JsonError};
use crate::sdp::logger::sdp_log;
use crate::sip::sip::SIPTransaction;

const SIP_LOG_MAX_STRING: usize = 8 * 1024;
const SIP_LOG_MAX_BYTES: usize = 128 * 1024;

/// Shared per-record budget for the sip object, sdp included.
pub(crate) struct SipLogBudget {
    remaining: usize,
    truncated: bool,
}

impl SipLogBudget {
    fn new() -> Self {
        Self {
            remaining: SIP_LOG_MAX_BYTES,
            truncated: false,
        }
    }

    pub(crate) fn set_string(
        &mut self, js: &mut JsonBuilder, key: &str, val: &str,
    ) -> Result<(), JsonError> {
        let len = val.len().min(SIP_LOG_MAX_STRING);
        let cost = len + 24;
        if cost > self.remaining {
            self.truncated = true;
            return Ok(());
        }
        self.remaining -= cost;
        if len < val.len() {
            self.truncated = true;
        }
        js.set_string_limited(key, val, SIP_LOG_MAX_STRING)?;
        Ok(())
    }

    /// Returns false when the budget is exhausted and nothing was logged.
    pub(crate) fn append_string(
        &mut self, js: &mut JsonBuilder, val: &str,
    ) -> Result<bool, JsonError> {
        let len = val.len().min(SIP_LOG_MAX_STRING);
        let cost = len + 8;
        if cost > self.remaining {
            self.truncated = true;
            return Ok(false);
        }
        self.remaining -= cost;
        if len < val.len() {
            self.truncated = true;
        }
        js.append_string_limited(val, SIP_LOG_MAX_STRING)?;
        Ok(true)
    }

    /// Reserve room for an array or object item.
    pub(crate) fn spend(&mut self, cost: usize) -> bool {
        if cost > self.remaining {
            self.truncated = true;
            return false;
        }
        self.remaining -= cost;
        true
    }
}

fn log(tx: &SIPTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    let mut budget = SipLogBudget::new();
    js.open_object("sip")?;

    if let Some(req) = &tx.request {
        budget.set_string(js, "method", &req.method)?;
        budget.set_string(js, "uri", &req.path)?;
        budget.set_string(js, "version", &req.version)?;

        if let Some(sdp_body) = &req.body {
            sdp_log(sdp_body, js, &mut budget)?;
        }
    }

    if let Some(req_line) = &tx.request_line {
        budget.set_string(js, "request_line", req_line)?;
    }

    if let Some(resp) = &tx.response {
        budget.set_string(js, "version", &resp.version)?;
        budget.set_string(js, "code", &resp.code)?;
        budget.set_string(js, "reason", &resp.reason)?;
        if let Some(sdp_body) = &resp.body {
            sdp_log(sdp_body, js, &mut budget)?;
        }
    }

    if let Some(resp_line) = &tx.response_line {
        budget.set_string(js, "response_line", resp_line)?;
    }

    if budget.truncated {
        js.set_bool("truncated", true)?;
    }

    js.close()?;

    Ok(())
}

#[no_mangle]
pub extern "C" fn SCSipLogJson(tx: &SIPTransaction, js: &mut JsonBuilder) -> bool {
    log(tx, js).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::direction::Direction;
    use crate::sdp::parser::SdpMessage;
    use crate::sip::parser::Request;
    use std::collections::HashMap;

    fn new_request(path: String, body: Option<SdpMessage>) -> Request {
        Request {
            method: "INVITE".to_string(),
            path,
            version: "SIP/2.0".to_string(),
            headers: HashMap::new(),
            request_line_len: 0,
            headers_len: 0,
            body_offset: 0,
            body_len: 0,
            body,
        }
    }

    fn new_sdp() -> SdpMessage {
        SdpMessage {
            version: 0,
            origin: "alice 1 1 IN IP4 192.168.1.10".to_string(),
            session_name: "-".to_string(),
            session_info: None,
            uri: None,
            email: None,
            phone_number: None,
            connection_data: None,
            bandwidths: None,
            time_description: Vec::new(),
            time_zone: None,
            encryption_key: None,
            attributes: None,
            media_description: None,
        }
    }

    fn log_tx(tx: &SIPTransaction) -> String {
        let mut js = JsonBuilder::try_new_object().unwrap();
        assert!(log(tx, &mut js).is_ok());
        js.close().unwrap();
        js.as_str().to_string()
    }

    #[test]
    fn test_long_uri_truncated() {
        let mut tx = SIPTransaction::new(1, Direction::ToServer);
        tx.request = Some(new_request("sip:".to_string() + &"a".repeat(20000), None));
        let out = log_tx(&tx);
        assert!(out.contains("[truncated 11812 additional bytes]"), "{out}");
        assert!(out.contains("\"truncated\":true"), "{out}");
    }

    #[test]
    fn test_encryption_key_redacted() {
        let mut tx = SIPTransaction::new(1, Direction::ToServer);
        let mut sdp = new_sdp();
        sdp.encryption_key = Some("clear:secretkey".to_string());
        tx.request = Some(new_request("sip:bob@example.com".to_string(), Some(sdp)));
        let out = log_tx(&tx);
        assert!(out.contains("\"encryption_key_redacted\":true"), "{out}");
        assert!(!out.contains("secretkey"), "{out}");
        assert!(!out.contains("\"encryption_key\":"), "{out}");
    }

    #[test]
    fn test_record_budget() {
        let mut tx = SIPTransaction::new(1, Direction::ToServer);
        let mut sdp = new_sdp();
        sdp.attributes = Some(vec!["a".repeat(8 * 1024); 32]);
        tx.request = Some(new_request("sip:bob@example.com".to_string(), Some(sdp)));
        let out = log_tx(&tx);
        assert!(out.len() < SIP_LOG_MAX_BYTES + 4096, "len {}", out.len());
        assert!(out.contains("\"truncated\":true"), "{out}");
    }
}

/* Copyright (C) 2020 Open Information Security Foundation
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

use super::ssh::{SSHError, SSHTransaction, SshHeader, SSH_MAX_BANNER_LEN};
use crate::jsonbuilder::{JsonBuilder, JsonError};

fn log_ssh_direction(js: &mut JsonBuilder, name: &str, hdr: &SshHeader) -> Result<(), JsonError> {
    // the direction object exists when it has data or a failure: a
    // failed direction may have parsed no banner at all
    if hdr.protover.is_empty() && hdr.error.is_none() {
        return Ok(());
    }
    js.open_object(name)?;
    if !hdr.protover.is_empty() {
        js.set_string_from_bytes_limited("proto_version", &hdr.protover, SSH_MAX_BANNER_LEN)?;
    }
    if !hdr.swver.is_empty() {
        js.set_string_from_bytes_limited("software_version", &hdr.swver, SSH_MAX_BANNER_LEN)?;
    }
    if let Some(error) = hdr.error {
        let err_name = match error {
            SSHError::InvalidBanner => "invalid_banner",
            SSHError::InvalidRecord => "invalid_record",
        };
        js.set_string("error", err_name)?;
    }
    if !hdr.hassh.is_empty() || !hdr.hassh_string.is_empty() {
        js.open_object("hassh")?;
        if !hdr.hassh.is_empty() {
            js.set_string_from_bytes("hash", &hdr.hassh)?;
        }
        if !hdr.hassh_string.is_empty() {
            js.set_string_from_bytes("string", &hdr.hassh_string)?;
        }
        js.close()?;
    }
    js.close()?;
    Ok(())
}

fn log_ssh(tx: &SSHTransaction, js: &mut JsonBuilder) -> Result<bool, JsonError> {
    js.open_object("ssh")?;
    let cli = !tx.cli_hdr.protover.is_empty() || tx.cli_hdr.error.is_some();
    let srv = !tx.srv_hdr.protover.is_empty() || tx.srv_hdr.error.is_some();
    if !cli && !srv {
        return Ok(false);
    }
    if cli {
        log_ssh_direction(js, "client", &tx.cli_hdr)?;
    }
    if srv {
        log_ssh_direction(js, "server", &tx.srv_hdr)?;
    }
    js.close()?;
    return Ok(true);
}

#[no_mangle]
pub unsafe extern "C" fn SCSshLogJson(tx: *mut std::os::raw::c_void, js: &mut JsonBuilder) -> bool {
    let tx = cast_pointer!(tx, SSHTransaction);
    if let Ok(x) = log_ssh(tx, js) {
        return x;
    }
    return false;
}

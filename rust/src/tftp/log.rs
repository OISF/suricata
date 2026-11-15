/* Copyright (C) 2017-2020 Open Information Security Foundation
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

// written by Clément Galland <clement.galland@epita.fr>

use crate::jsonbuilder::{JsonBuilder, JsonError};
use crate::tftp::tftp::TFTPTransaction;
fn tftp_log_request_with(
    tx: &TFTPTransaction, jb: &mut JsonBuilder, filenames: bool,
) -> Result<(), JsonError> {
    jb.open_object("tftp")?;
    match tx.opcode {
        1 => jb.set_string("packet", "read")?,
        2 => jb.set_string("packet", "write")?,
        _ => jb.set_string("packet", "error")?,
    };
    if filenames {
        jb.set_string("file", tx.filename.as_str())?;
    }
    jb.set_string("mode", tx.mode.as_str())?;
    jb.close()?;
    Ok(())
}

#[no_mangle]
pub extern "C" fn SCTftpLogJsonRequest(tx: &TFTPTransaction, jb: &mut JsonBuilder) -> bool {
    tftp_log_request_with(tx, jb, false).is_ok()
}

#[no_mangle]
pub extern "C" fn SCTftpLogJsonRequestFlags(
    tx: &TFTPTransaction, jb: &mut JsonBuilder, filenames: bool,
) -> bool {
    tftp_log_request_with(tx, jb, filenames).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::direction::Direction;

    fn new_tx() -> TFTPTransaction {
        TFTPTransaction::new(
            1,
            "rfc1350.txt".to_string(),
            "octet".to_string(),
            Direction::ToServer,
        )
    }

    #[test]
    fn test_filenames_off_by_default() {
        let tx = new_tx();
        let mut jb = JsonBuilder::try_new_object().unwrap();
        tftp_log_request_with(&tx, &mut jb, false).unwrap();
        assert!(!jb.as_str().contains("rfc1350.txt"));
        assert!(jb.as_str().contains("\"packet\":\"read\""));
    }

    #[test]
    fn test_filenames_enabled() {
        let tx = new_tx();
        let mut jb = JsonBuilder::try_new_object().unwrap();
        tftp_log_request_with(&tx, &mut jb, true).unwrap();
        assert!(jb.as_str().contains("\"file\":\"rfc1350.txt\""));
    }
}

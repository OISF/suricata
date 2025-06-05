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

use crate::jsonbuilder::{JsonBuilder, JsonError};
use crate::krb::krb5::{test_weak_encryption, KRB5Transaction};

fn krb5_log_response(jsb: &mut JsonBuilder, tx: &KRB5Transaction) -> Result<(), JsonError> {
    jsb.open_object("krb5")?;
    match tx.error_code {
        Some(c) => {
            jsb.set_string("msg_type", &format!("{:?}", tx.msg_type))?;
            if let Some(req_type) = tx.req_type {
                jsb.set_string("failed_request", &format!("{:?}", req_type))?;
            } else {
                // In case we capture the response but not the request
                // we can't know the failed request type, since it could be
                // AS-REQ or TGS-REQ
                jsb.set_string("failed_request", "UNKNOWN")?;
            }
            jsb.set_string("error_code", &format!("{:?}", c))?;
        }
        None => {
            jsb.set_string("msg_type", &format!("{:?}", tx.msg_type))?;
        }
    }
    let cname = match tx.cname {
        Some(ref x) => format!("{}", x),
        None => "<empty>".to_owned(),
    };
    let realm = match tx.realm {
        Some(ref x) => x.0.to_string(),
        None => "<empty>".to_owned(),
    };
    let sname = match tx.sname {
        Some(ref x) => format!("{}", x),
        None => "<empty>".to_owned(),
    };
    let encryption = match tx.etype {
        Some(ref x) => format!("{:?}", x),
        None => "<none>".to_owned(),
    };
    jsb.set_string("cname", &cname)?;
    jsb.set_string("realm", &realm)?;
    jsb.set_string("sname", &sname)?;
    jsb.set_string("encryption", &encryption)?;
    jsb.set_bool(
        "weak_encryption",
        tx.etype.is_some_and(test_weak_encryption),
    )?;
    if let Some(x) = tx.ticket_etype {
        let refs = format!("{:?}", x);
        jsb.set_string("ticket_encryption", &refs)?;
        jsb.set_bool("ticket_weak_encryption", test_weak_encryption(x))?;
    }
    jsb.close()?;

    return Ok(());
}

#[no_mangle]
pub extern "C" fn SCKrb5LogJsonResponse(tx: &KRB5Transaction, jsb: &mut JsonBuilder) -> bool {
    krb5_log_response(jsb, tx).is_ok()
}

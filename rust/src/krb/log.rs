/* Copyright (C) 2018-2022 Open Information Security Foundation
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
use crate::krb::krb5::{KRB5State,KRB5Transaction,test_weak_encryption};

fn krb5_log_response(jsb: &mut JsonBuilder, tx: &mut KRB5Transaction) -> Result<(), JsonError>
{
    match tx.error_code {
        Some(c) => {
            jsb.set_string("msg_type", "KRB_ERROR")?;
            jsb.set_string("failed_request", &format!("{:?}", tx.msg_type))?;
            jsb.set_string("error_code", &format!("{:?}", c))?;
        },
        None    => { jsb.set_string("msg_type", &format!("{:?}", tx.msg_type))?; },
    }
    let cname = match tx.cname {
        Some(ref x) => format!("{}", x),
        None        => "<empty>".to_owned(),
    };
    let realm = match tx.realm {
        Some(ref x) => x.0.to_string(),
        None        => "<empty>".to_owned(),
    };
    let sname = match tx.sname {
        Some(ref x) => format!("{}", x),
        None        => "<empty>".to_owned(),
    };
    let encryption = match tx.etype {
        Some(ref x) => format!("{:?}", x),
        None        => "<none>".to_owned(),
    };
    jsb.set_string("cname", &cname)?;
    jsb.set_string("realm", &realm)?;
    jsb.set_string("sname", &sname)?;
    jsb.set_string("encryption", &encryption)?;
    jsb.set_bool("weak_encryption", tx.etype.map_or(false,test_weak_encryption))?;
    if let Some(x) = tx.ticket_etype {
        let refs = format!("{:?}", x);
        jsb.set_string("ticket_encryption", &refs)?;
        jsb.set_bool("ticket_weak_encryption", test_weak_encryption(x))?;
    }

    return Ok(());
}

#[no_mangle]
pub extern "C" fn rs_krb5_log_json_response(jsb: &mut JsonBuilder, _state: &mut KRB5State, tx: &mut KRB5Transaction) -> bool
{
    krb5_log_response(jsb, tx).is_ok()
}

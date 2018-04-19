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

use json::*;
use krb::krb5::{KRB5State,KRB5Transaction};

#[no_mangle]
pub extern "C" fn rs_krb5_log_json_response(_state: &mut KRB5State, tx: &mut KRB5Transaction) -> *mut JsonT
{
    let js = Json::object();
    match tx.error_code {
        Some(c) => {
            js.set_string("msg_type", "KRB_ERROR");
            js.set_string("failed_request", &format!("{:?}", tx.msg_type));
            js.set_string("error_code", &format!("{}", c));
        },
        None    => { js.set_string("msg_type", &format!("{:?}", tx.msg_type)); },
    }
    let cname = match tx.cname {
        Some(ref x) => format!("{}", x),
        None        => "<empty>".to_owned(),
    };
    let realm = match tx.realm {
        Some(ref x) => format!("{}", x.0),
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
    js.set_string("cname", &cname);
    js.set_string("realm", &realm);
    js.set_string("sname", &sname);
    js.set_string("encryption", &encryption);
    return js.unwrap();
}


/* Copyright (C) 2026 Open Information Security Foundation
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

//! App-layer utils.

#[macro_export]
macro_rules! export_tx_data_get {
    ($name:ident, $type:ty) => {
        unsafe extern "C" fn $name(
            tx: *mut std::os::raw::c_void,
        ) -> *mut suricata_sys::sys::AppLayerTxData {
            let tx = &mut *(tx as *mut $type);
            &mut tx.tx_data.0
        }
    };
}

#[macro_export]
macro_rules! export_state_data_get {
    ($name:ident, $type:ty) => {
        unsafe extern "C" fn $name(
            state: *mut std::os::raw::c_void,
        ) -> *mut suricata_sys::sys::AppLayerStateData {
            let state = &mut *(state as *mut $type);
            &mut state.state_data
        }
    };
}

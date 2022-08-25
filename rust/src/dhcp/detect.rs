/* Copyright (C) 2022 Open Information Security Foundation
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

use super::dhcp::{
    DHCPTransaction, DHCP_OPT_ADDRESS_TIME, DHCP_OPT_REBINDING_TIME, DHCP_OPT_RENEWAL_TIME,
};
use super::parser::DHCPOptionWrapper;

#[no_mangle]
pub unsafe extern "C" fn rs_dhcp_tx_get_leasetime(
    tx: &mut DHCPTransaction, leasetime: *mut u64,
) -> u8 {
    for option in &tx.message.options {
        if option.code == DHCP_OPT_ADDRESS_TIME {
            if let DHCPOptionWrapper::TimeValue(ref time_value) = option.option {
                *leasetime = time_value.seconds as u64;
                return 1;
            }
        }
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_dhcp_tx_get_rebinding_time(
    tx: &mut DHCPTransaction, res: *mut u64,
) -> u8 {
    for option in &tx.message.options {
        if option.code == DHCP_OPT_REBINDING_TIME {
            if let DHCPOptionWrapper::TimeValue(ref time_value) = option.option {
                *res = time_value.seconds as u64;
                return 1;
            }
        }
    }
    return 0;
}

#[no_mangle]
pub unsafe extern "C" fn rs_dhcp_tx_get_renewal_time(
    tx: &mut DHCPTransaction, res: *mut u64,
) -> u8 {
    for option in &tx.message.options {
        if option.code == DHCP_OPT_RENEWAL_TIME {
            if let DHCPOptionWrapper::TimeValue(ref time_value) = option.option {
                *res = time_value.seconds as u64;
                return 1;
            }
        }
    }
    return 0;
}

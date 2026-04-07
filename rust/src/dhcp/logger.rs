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

use std;

use crate::dhcp::dhcp::*;
use crate::dhcp::parser::{DHCPOptGeneric, DHCPOptionWrapper};
use crate::dns::log::dns_print_addr;
use crate::jsonbuilder::{JsonBuilder, JsonError};

fn get_type(tx: &DHCPTransaction) -> Option<u8> {
    let options = &tx.message.options;
    for option in options {
        let code = option.code;
        #[allow(clippy::single_match)]
        match &option.option {
            DHCPOptionWrapper::Generic(option) =>
            {
                #[allow(clippy::single_match)]
                match code {
                    DHCP_OPT_TYPE => {
                        if !option.data.is_empty() {
                            return Some(option.data[0]);
                        }
                    }
                    _ => {}
                }
            }
            _ => {}
        }
    }
    return None;
}

fn do_log(extended: bool, tx: &DHCPTransaction) -> bool {
    if !extended {
        return matches!(get_type(tx), Some(DHCP_TYPE_ACK));
    }
    return true;
}

fn log(extended: bool, tx: &DHCPTransaction, js: &mut JsonBuilder) -> Result<(), JsonError> {
    let header = &tx.message.header;
    let options = &tx.message.options;

    js.open_object("dhcp")?;

    match header.opcode {
        BOOTP_REQUEST => {
            js.set_string("type", "request")?;
        }
        BOOTP_REPLY => {
            js.set_string("type", "reply")?;
        }
        _ => {
            js.set_string("type", "<unknown>")?;
        }
    }

    js.set_uint("id", header.txid as u64)?;
    js.set_string("client_mac", &format_addr_hex(&header.clienthw))?;
    js.set_string("assigned_ip", &dns_print_addr(&header.yourip))?;

    if extended {
        js.set_string("client_ip", &dns_print_addr(&header.clientip))?;
        if header.opcode == BOOTP_REPLY {
            js.set_string("relay_ip", &dns_print_addr(&header.giaddr))?;
            js.set_string("next_server_ip", &dns_print_addr(&header.serverip))?;
        }
    }

    for option in options {
        let code = option.code;
        match option.option {
            DHCPOptionWrapper::ClientId(ref clientid) => {
                js.set_string("client_id", &format_addr_hex(&clientid.data))?;
            }
            DHCPOptionWrapper::TimeValue(ref time_value) => match code {
                DHCP_OPT_ADDRESS_TIME => {
                    if extended {
                        js.set_uint("lease_time", time_value.seconds as u64)?;
                    }
                }
                DHCP_OPT_REBINDING_TIME => {
                    if extended {
                        js.set_uint("rebinding_time", time_value.seconds as u64)?;
                    }
                }
                DHCP_OPT_RENEWAL_TIME => {
                    js.set_uint("renewal_time", time_value.seconds as u64)?;
                }
                _ => {}
            },
            DHCPOptionWrapper::Generic(ref option) => match code {
                DHCP_OPT_SUBNET_MASK => {
                    if extended {
                        js.set_string("subnet_mask", &dns_print_addr(&option.data))?;
                    }
                }
                DHCP_OPT_HOSTNAME => {
                    if !option.data.is_empty() {
                        js.set_string_from_bytes("hostname", &option.data)?;
                    }
                }
                DHCP_OPT_TYPE => {
                    log_opt_type(js, option)?;
                }
                DHCP_OPT_REQUESTED_IP => {
                    if extended {
                        js.set_string("requested_ip", &dns_print_addr(&option.data))?;
                    }
                }
                DHCP_OPT_PARAMETER_LIST => {
                    if extended {
                        log_opt_parameters(js, option)?;
                    }
                }
                DHCP_OPT_DNS_SERVER => {
                    if extended {
                        log_opt_dns_server(js, option)?;
                    }
                }
                DHCP_OPT_ROUTERS => {
                    if extended {
                        log_opt_routers(js, option)?;
                    }
                }
                DHCP_OPT_VENDOR_CLASS_ID => {
                    if extended && !option.data.is_empty() {
                        js.set_string_from_bytes("vendor_class_identifier", &option.data)?;
                    }
                }
                _ => {}
            },
            _ => {}
        }
    }

    js.close()?;

    return Ok(());
}

fn log_opt_type(js: &mut JsonBuilder, option: &DHCPOptGeneric) -> Result<(), JsonError> {
    if !option.data.is_empty() {
        let dhcp_type = match option.data[0] {
            DHCP_TYPE_DISCOVER => "discover",
            DHCP_TYPE_OFFER => "offer",
            DHCP_TYPE_REQUEST => "request",
            DHCP_TYPE_DECLINE => "decline",
            DHCP_TYPE_ACK => "ack",
            DHCP_TYPE_NAK => "nak",
            DHCP_TYPE_RELEASE => "release",
            DHCP_TYPE_INFORM => "inform",
            _ => "unknown",
        };
        js.set_string("dhcp_type", dhcp_type)?;
    }
    Ok(())
}

fn log_opt_parameters(js: &mut JsonBuilder, option: &DHCPOptGeneric) -> Result<(), JsonError> {
    js.open_array("params")?;
    for i in &option.data {
        let param = match *i {
            DHCP_PARAM_SUBNET_MASK => "subnet_mask",
            DHCP_PARAM_ROUTER => "router",
            DHCP_PARAM_DNS_SERVER => "dns_server",
            DHCP_PARAM_DOMAIN => "domain",
            DHCP_PARAM_ARP_TIMEOUT => "arp_timeout",
            DHCP_PARAM_NTP_SERVER => "ntp_server",
            DHCP_PARAM_TFTP_SERVER_NAME => "tftp_server_name",
            DHCP_PARAM_TFTP_SERVER_IP => "tftp_server_ip",
            _ => "",
        };
        if !param.is_empty() {
            js.append_string(param)?;
        }
    }
    js.close()?;
    Ok(())
}

fn log_opt_dns_server(js: &mut JsonBuilder, option: &DHCPOptGeneric) -> Result<(), JsonError> {
    js.open_array("dns_servers")?;
    for i in 0..(option.data.len() / 4) {
        let val = dns_print_addr(&option.data[(i * 4)..(i * 4) + 4]);
        js.append_string(&val)?;
    }
    js.close()?;
    Ok(())
}

fn log_opt_routers(js: &mut JsonBuilder, option: &DHCPOptGeneric) -> Result<(), JsonError> {
    js.open_array("routers")?;
    for i in 0..(option.data.len() / 4) {
        let val = dns_print_addr(&option.data[(i * 4)..(i * 4) + 4]);
        js.append_string(&val)?;
    }
    js.close()?;
    Ok(())
}

fn format_addr_hex(input: &[u8]) -> String {
    let parts: Vec<String> = input.iter().map(|b| format!("{:02x}", b)).collect();
    return parts.join(":");
}

#[no_mangle]
pub unsafe extern "C" fn SCDhcpLoggerLog(
    extended: bool, tx: *mut std::os::raw::c_void, js: &mut JsonBuilder,
) -> bool {
    let tx = cast_pointer!(tx, DHCPTransaction);
    log(extended, tx, js).is_ok()
}

#[no_mangle]
pub unsafe extern "C" fn SCDhcpLoggerDoLog(extended: bool, tx: *mut std::os::raw::c_void) -> bool {
    let tx = cast_pointer!(tx, DHCPTransaction);
    do_log(extended, tx)
}

#[no_mangle]
pub unsafe extern "C" fn SCDhcpLogJson(
    tx: *mut std::os::raw::c_void, js: &mut JsonBuilder,
) -> bool {
    let tx = cast_pointer!(tx, DHCPTransaction);
    log(true, tx, js).is_ok()
}

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
use std::os::raw::c_void;

use dhcp::dhcp::*;
use dhcp::parser::{DHCPOptionWrapper,DHCPOptGeneric};
use dns::log::dns_print_addr;
use json::*;
use conf::ConfNode;

pub struct DHCPLogger {
    extended: bool,
}

impl DHCPLogger {
    
    pub fn new(conf: ConfNode) -> DHCPLogger {
        return DHCPLogger{
            extended: conf.get_child_bool("extended"),
        };
    }

    fn get_type(&self, tx: &DHCPTransaction) -> Option<u8> {
        let options = &tx.message.options;
        for option in options {
            let code = option.code;
            match &option.option {
                &DHCPOptionWrapper::Generic(ref option) => {
                    match code {
                        DHCP_OPT_TYPE => {
                            if option.data.len() > 0 {
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

    fn do_log(&self, tx: &DHCPTransaction) -> bool {
        if !self.extended {
            match self.get_type(tx) {
                Some(t) => {
                    match t {
                        DHCP_TYPE_ACK => {
                            return true;
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
            return false;
        }
        return true;
    }

    pub fn log(&self, tx: &DHCPTransaction) -> Option<Json> {
        if !self.do_log(tx) {
            return None;
        }
        
        let header = &tx.message.header;
        let options = &tx.message.options;
        let js = Json::object();

        match header.opcode {
            BOOTP_REQUEST => {
                js.set_string("type", "request");
            }
            BOOTP_REPLY => {
                js.set_string("type", "reply");
            }
            _ => {
                js.set_string("type", "<unknown>");
            }
        }
        
        js.set_integer("id", header.txid as u64);
        js.set_string("client_mac",
                      &format_addr_hex(&header.clienthw.to_vec()));
        js.set_string("assigned_ip", &dns_print_addr(&header.yourip));

        if self.extended {
            js.set_string("client_ip", &dns_print_addr(&header.clientip));
            if header.opcode == BOOTP_REPLY {
                js.set_string("relay_ip",
                              &dns_print_addr(&header.giaddr));
                js.set_string("next_server_ip",
                              &dns_print_addr(&header.serverip));
            }
        }
        
        for option in options {
            let code = option.code;
            match &option.option {
                &DHCPOptionWrapper::ClientId(ref clientid) => {
                    js.set_string("client_id",
                                  &format_addr_hex(&clientid.data));
                }
                &DHCPOptionWrapper::TimeValue(ref time_value) => {
                    match code {
                        DHCP_OPT_ADDRESS_TIME => {
                            if self.extended {
                                js.set_integer("lease_time",
                                               time_value.seconds as u64);
                            }
                        }
                        DHCP_OPT_REBINDING_TIME => {
                            if self.extended {
                                js.set_integer("rebinding_time",
                                               time_value.seconds as u64);
                            }
                        }
                        DHCP_OPT_RENEWAL_TIME => {
                            js.set_integer("renewal_time",
                                           time_value.seconds as u64);
                        }
                        _ => {}
                    }
                }
                &DHCPOptionWrapper::Generic(ref option) => {
                    match code {
                        DHCP_OPT_SUBNET_MASK => {
                            if self.extended {
                                js.set_string("subnet_mask",
                                              &dns_print_addr(&option.data));
                            }
                        }
                        DHCP_OPT_HOSTNAME => {
                            if option.data.len() > 0 {
                                js.set_string_from_bytes("hostname",
                                                         &option.data);
                            }
                        }
                        DHCP_OPT_TYPE => {
                            self.log_opt_type(&js, option);
                        }
                        DHCP_OPT_REQUESTED_IP => {
                            if self.extended {
                                js.set_string("requested_ip",
                                              &dns_print_addr(&option.data));
                            }
                        }
                        DHCP_OPT_PARAMETER_LIST => {
                            if self.extended {
                                self.log_opt_parameters(&js, option);
                            }
                        }
                        DHCP_OPT_DNS_SERVER => {
                            if self.extended {
                                self.log_opt_dns_server(&js, option);
                            }
                        }
                        DHCP_OPT_ROUTERS => {
                            if self.extended {
                                self.log_opt_routers(&js, option);
                            }
                        }
                        _ => {}
                    }
                }
                _ => {}
            }
        }
        
        return Some(js);
    }

    fn log_opt_type(&self, js: &Json, option: &DHCPOptGeneric) {
        if option.data.len() > 0 {
            let dhcp_type = match option.data[0] {
                DHCP_TYPE_DISCOVER => "discover",
                DHCP_TYPE_OFFER => "offer",
                DHCP_TYPE_REQUEST => "request",
                DHCP_TYPE_DECLINE => "decline",
                DHCP_TYPE_ACK => "ack",
                DHCP_TYPE_NAK => "nak",
                DHCP_TYPE_RELEASE => "release",
                DHCP_TYPE_INFORM => "inform",
                _ => "unknown"
            };
            js.set_string("dhcp_type", dhcp_type);
        }
    }

    fn log_opt_parameters(&self, js: &Json, option: &DHCPOptGeneric) {
        let params = Json::array();
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
                _ => ""
            };
            if param.len() > 0 {
                params.array_append_string(param);
            }
        }
        js.set("params", params);
    }
    
    fn log_opt_dns_server(&self, js: &Json, option: &DHCPOptGeneric) {
        let servers = Json::array();
        for i in 0..(option.data.len() / 4) {
            servers.array_append_string(&dns_print_addr(
                &option.data[(i * 4)..(i * 4) + 4].to_vec()))
        }
        js.set("dns_servers", servers);
    }
    
    fn log_opt_routers(&self, js: &Json, option: &DHCPOptGeneric) {
        let routers = Json::array();
        for i in 0..(option.data.len() / 4) {
            routers.array_append_string(&dns_print_addr(
                &option.data[(i * 4)..(i * 4) + 4].to_vec()))
        }
        js.set("routers", routers);
    }

}

fn format_addr_hex(input: &Vec<u8>) -> String {
    let parts: Vec<String> = input.iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    return parts.join(":");
}

#[no_mangle]
pub extern "C" fn rs_dhcp_logger_new(conf: *const c_void) -> *mut std::os::raw::c_void {
    let conf = ConfNode::wrap(conf);
    let boxed = Box::new(DHCPLogger::new(conf));
    return unsafe{std::mem::transmute(boxed)};
}

#[no_mangle]
pub extern "C" fn rs_dhcp_logger_free(logger: *mut std::os::raw::c_void) {
    let _: Box<DHCPLogger> = unsafe{std::mem::transmute(logger)};
}

#[no_mangle]
pub extern "C" fn rs_dhcp_logger_log(logger: *mut std::os::raw::c_void,
                                     tx: *mut std::os::raw::c_void) -> *mut JsonT {
    let logger = cast_pointer!(logger, DHCPLogger);
    let tx = cast_pointer!(tx, DHCPTransaction);
    match logger.log(tx) {
        Some(js) => {
            return js.unwrap();
        }
        _ => {
            return std::ptr::null_mut();
        }
    }
}

use super::suricata;
use super::zabbix::rs_zabbix_register_parser;
use crate::detect::rs_zabbix_keywords_register;
use crate::log::rs_zabbix_log;
use crate::suricata::{SCAppLayerPlugin, SCPlugin, SCPluginRegisterAppLayer};
use crate::util::SCLog;

extern "C" fn zabbix_plugin_init() {
    SCLog!(suricata::Level::Notice, "Initializing zabbix plugin");
    let plugin = SCAppLayerPlugin {
        name: b"zabbix\0".as_ptr() as *const libc::c_char,
        logname: b"JsonZabbixLog\0".as_ptr() as *const libc::c_char,
        confname: b"eve-log.zabbix\0".as_ptr() as *const libc::c_char,
        Register: rs_zabbix_register_parser,
        Logger: rs_zabbix_log,
        KeywordsRegister: rs_zabbix_keywords_register,
    };
    unsafe {
        if SCPluginRegisterAppLayer(Box::into_raw(Box::new(plugin))) != 0 {
            println!("Failed to register zabbix plugin");
        }
    }
}

#[no_mangle]
extern "C" fn SCPluginRegister() -> *const SCPlugin {
    let plugin = SCPlugin {
        name: b"zabbix\0".as_ptr() as *const libc::c_char,
        license: b"MIT\0".as_ptr() as *const libc::c_char,
        author: b"Philippe Antoine\0".as_ptr() as *const libc::c_char,
        Init: zabbix_plugin_init,
    };
    Box::into_raw(Box::new(plugin))
}

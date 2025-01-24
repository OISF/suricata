use super::template::template_register_parser;
use crate::detect::detect_template_register;
use crate::log::template_logger_log;
use suricata::plugin::{
    SCAppLayerPlugin, SCPlugin, SCPluginRegisterAppLayer, SC_PLUGIN_API_VERSION,
};
use suricata::{SCLogError, SCLogNotice};

extern "C" fn altemplate_plugin_init() {
    suricata::plugin::init();
    SCLogNotice!("Initializing altemplate plugin");
    let plugin = SCAppLayerPlugin {
        version: SC_PLUGIN_API_VERSION, // api version for suricata compatibility
        name: b"altemplate\0".as_ptr() as *const libc::c_char,
        logname: b"JsonaltemplateLog\0".as_ptr() as *const libc::c_char,
        confname: b"eve-log.altemplate\0".as_ptr() as *const libc::c_char,
        Register: template_register_parser,
        Logger: template_logger_log,
        KeywordsRegister: detect_template_register,
    };
    unsafe {
        if SCPluginRegisterAppLayer(Box::into_raw(Box::new(plugin))) != 0 {
            SCLogError!("Failed to register altemplate plugin");
        }
    }
}

#[no_mangle]
extern "C" fn SCPluginRegister() -> *const SCPlugin {
    let plugin = SCPlugin {
        name: b"altemplate\0".as_ptr() as *const libc::c_char,
        license: b"MIT\0".as_ptr() as *const libc::c_char,
        author: b"Philippe Antoine\0".as_ptr() as *const libc::c_char,
        Init: altemplate_plugin_init,
    };
    Box::into_raw(Box::new(plugin))
}

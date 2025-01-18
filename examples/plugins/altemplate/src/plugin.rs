use super::suricata;
use super::template::rs_template_register_parser;
use crate::detect::ScDetectTemplateRegister;
use crate::log::rs_template_logger_log;
use crate::suricata::{SCAppLayerPlugin, SCLog, SCPlugin, SCPluginRegisterAppLayer};

extern "C" fn altemplate_plugin_init() {
    SCLog!(suricata::Level::Notice, "Initializing altemplate plugin");
    let plugin = SCAppLayerPlugin {
        version: 8, // api version for suricata compatibility
        name: b"altemplate\0".as_ptr() as *const libc::c_char,
        logname: b"JsonaltemplateLog\0".as_ptr() as *const libc::c_char,
        confname: b"eve-log.altemplate\0".as_ptr() as *const libc::c_char,
        Register: rs_template_register_parser,
        Logger: rs_template_logger_log,
        KeywordsRegister: ScDetectTemplateRegister,
    };
    unsafe {
        if SCPluginRegisterAppLayer(Box::into_raw(Box::new(plugin))) != 0 {
            println!("Failed to register altemplate plugin");
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

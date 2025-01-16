// This file is automatically generated. Do not edit.

#[repr(u32)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum AppProtoEnum {
    ALPROTO_UNKNOWN = 0,
    ALPROTO_FAILED = 1,
    ALPROTO_HTTP1 = 2,
    ALPROTO_FTP = 3,
    ALPROTO_SMTP = 4,
    ALPROTO_TLS = 5,
    ALPROTO_SSH = 6,
    ALPROTO_IMAP = 7,
    ALPROTO_JABBER = 8,
    ALPROTO_SMB = 9,
    ALPROTO_DCERPC = 10,
    ALPROTO_IRC = 11,
    ALPROTO_DNS = 12,
    ALPROTO_MODBUS = 13,
    ALPROTO_ENIP = 14,
    ALPROTO_DNP3 = 15,
    ALPROTO_NFS = 16,
    ALPROTO_NTP = 17,
    ALPROTO_FTPDATA = 18,
    ALPROTO_TFTP = 19,
    ALPROTO_IKE = 20,
    ALPROTO_KRB5 = 21,
    ALPROTO_QUIC = 22,
    ALPROTO_DHCP = 23,
    ALPROTO_SIP = 24,
    ALPROTO_RFB = 25,
    ALPROTO_MQTT = 26,
    ALPROTO_PGSQL = 27,
    ALPROTO_TELNET = 28,
    ALPROTO_WEBSOCKET = 29,
    ALPROTO_LDAP = 30,
    ALPROTO_DOH2 = 31,
    ALPROTO_TEMPLATE = 32,
    ALPROTO_RDP = 33,
    ALPROTO_HTTP2 = 34,
    ALPROTO_BITTORRENT_DHT = 35,
    ALPROTO_POP3 = 36,
    ALPROTO_HTTP = 37,
    ALPROTO_MAX_STATIC = 38,
}
pub type AppProto = u16;
extern "C" {
    #[doc = " \\brief Maps the ALPROTO_*, to its string equivalent.\n\n \\param alproto App layer protocol id.\n\n \\retval String equivalent for the alproto."]
    pub fn AppProtoToString(alproto: AppProto) -> *const ::std::os::raw::c_char;
}
extern "C" {
    pub fn AppProtoNewProtoFromString(proto_name: *const ::std::os::raw::c_char) -> AppProto;
}
extern "C" {
    pub fn AppProtoRegisterProtoString(
        alproto: AppProto, proto_name: *const ::std::os::raw::c_char,
    );
}
#[doc = " Structure to define a Suricata plugin."]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SCPlugin_ {
    pub name: *const ::std::os::raw::c_char,
    pub license: *const ::std::os::raw::c_char,
    pub author: *const ::std::os::raw::c_char,
    pub Init: ::std::option::Option<unsafe extern "C" fn()>,
}
#[doc = " Structure to define a Suricata plugin."]
pub type SCPlugin = SCPlugin_;
pub type SCPluginRegisterFunc = ::std::option::Option<unsafe extern "C" fn() -> *mut SCPlugin>;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SCCapturePlugin_ {
    pub name: *mut ::std::os::raw::c_char,
    pub Init: ::std::option::Option<
        unsafe extern "C" fn(
            args: *const ::std::os::raw::c_char,
            plugin_slot: ::std::os::raw::c_int,
            receive_slot: ::std::os::raw::c_int,
            decode_slot: ::std::os::raw::c_int,
        ),
    >,
    pub ThreadInit: ::std::option::Option<
        unsafe extern "C" fn(
            ctx: *mut ::std::os::raw::c_void,
            thread_id: ::std::os::raw::c_int,
            thread_ctx: *mut *mut ::std::os::raw::c_void,
        ) -> ::std::os::raw::c_int,
    >,
    pub ThreadDeinit: ::std::option::Option<
        unsafe extern "C" fn(
            ctx: *mut ::std::os::raw::c_void,
            thread_ctx: *mut ::std::os::raw::c_void,
        ) -> ::std::os::raw::c_int,
    >,
    pub GetDefaultMode:
        ::std::option::Option<unsafe extern "C" fn() -> *const ::std::os::raw::c_char>,
    pub entries: SCCapturePlugin___bindgen_ty_1,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SCCapturePlugin___bindgen_ty_1 {
    pub tqe_next: *mut SCCapturePlugin_,
    pub tqe_prev: *mut *mut SCCapturePlugin_,
}
pub type SCCapturePlugin = SCCapturePlugin_;
extern "C" {
    pub fn SCPluginRegisterCapture(arg1: *mut SCCapturePlugin) -> ::std::os::raw::c_int;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SCAppLayerPlugin_ {
    pub version: u64,
    pub name: *mut ::std::os::raw::c_char,
    pub Register: ::std::option::Option<unsafe extern "C" fn()>,
    pub KeywordsRegister: ::std::option::Option<unsafe extern "C" fn()>,
    pub logname: *mut ::std::os::raw::c_char,
    pub confname: *mut ::std::os::raw::c_char,
    pub dir: u8,
    pub Logger: ::std::option::Option<
        unsafe extern "C" fn(
            tx: *const ::std::os::raw::c_void,
            jb: *mut ::std::os::raw::c_void,
        ) -> bool,
    >,
}
pub type SCAppLayerPlugin = SCAppLayerPlugin_;
extern "C" {
    pub fn SCPluginRegisterAppLayer(arg1: *mut SCAppLayerPlugin) -> ::std::os::raw::c_int;
}
#[repr(u32)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum SCOutputJsonLogDirection {
    LOG_DIR_PACKET = 0,
    LOG_DIR_FLOW = 1,
    LOG_DIR_FLOW_TOCLIENT = 2,
    LOG_DIR_FLOW_TOSERVER = 3,
}
pub type EveJsonSimpleTxLogFunc = ::std::option::Option<
    unsafe extern "C" fn(
        arg1: *const ::std::os::raw::c_void,
        arg2: *mut ::std::os::raw::c_void,
    ) -> bool,
>;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct EveJsonSimpleAppLayerLogger {
    pub LogTx: EveJsonSimpleTxLogFunc,
    pub name: *const ::std::os::raw::c_char,
}
extern "C" {
    pub fn SCEveJsonSimpleGetLogger(alproto: AppProto) -> *mut EveJsonSimpleAppLayerLogger;
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct EveJsonTxLoggerRegistrationData {
    pub confname: *const ::std::os::raw::c_char,
    pub logname: *const ::std::os::raw::c_char,
    pub alproto: AppProto,
    pub dir: u8,
    pub LogTx: EveJsonSimpleTxLogFunc,
}
extern "C" {
    pub fn SCOutputPreRegisterLogger(
        reg_data: EveJsonTxLoggerRegistrationData,
    ) -> ::std::os::raw::c_int;
}

// This file is automatically generated. Do not edit.

pub const SC_PACKAGE_VERSION: &[u8; 10] = b"8.0.0-dev\0";
pub type __intmax_t = ::std::os::raw::c_long;
pub type intmax_t = __intmax_t;
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
    ALPROTO_SNMP = 24,
    ALPROTO_SIP = 25,
    ALPROTO_RFB = 26,
    ALPROTO_MQTT = 27,
    ALPROTO_PGSQL = 28,
    ALPROTO_TELNET = 29,
    ALPROTO_WEBSOCKET = 30,
    ALPROTO_LDAP = 31,
    ALPROTO_DOH2 = 32,
    ALPROTO_TEMPLATE = 33,
    ALPROTO_RDP = 34,
    ALPROTO_HTTP2 = 35,
    ALPROTO_BITTORRENT_DHT = 36,
    ALPROTO_POP3 = 37,
    ALPROTO_HTTP = 38,
    ALPROTO_MAX_STATIC = 39,
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
pub const SC_API_VERSION: u64 = 2048;
#[doc = " Structure to define a Suricata plugin."]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SCPlugin_ {
    pub version: u64,
    pub suricata_version: *const ::std::os::raw::c_char,
    pub name: *const ::std::os::raw::c_char,
    pub plugin_version: *const ::std::os::raw::c_char,
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
    pub name: *const ::std::os::raw::c_char,
    pub Register: ::std::option::Option<unsafe extern "C" fn()>,
    pub KeywordsRegister: ::std::option::Option<unsafe extern "C" fn()>,
    pub logname: *const ::std::os::raw::c_char,
    pub confname: *const ::std::os::raw::c_char,
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
#[doc = " Structure of a configuration parameter."]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SCConfNode_ {
    pub name: *mut ::std::os::raw::c_char,
    pub val: *mut ::std::os::raw::c_char,
    pub is_seq: ::std::os::raw::c_int,
    pub final_: ::std::os::raw::c_int,
    pub parent: *mut SCConfNode_,
    pub head: SCConfNode___bindgen_ty_1,
    pub next: SCConfNode___bindgen_ty_2,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SCConfNode___bindgen_ty_1 {
    pub tqh_first: *mut SCConfNode_,
    pub tqh_last: *mut *mut SCConfNode_,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SCConfNode___bindgen_ty_2 {
    pub tqe_next: *mut SCConfNode_,
    pub tqe_prev: *mut *mut SCConfNode_,
}
#[doc = " Structure of a configuration parameter."]
pub type SCConfNode = [u64; 8usize];
extern "C" {
    pub fn SCConfInit();
}
extern "C" {
    pub fn SCConfDeInit();
}
extern "C" {
    pub fn SCConfGetRootNode() -> *mut SCConfNode;
}
extern "C" {
    pub fn SCConfGet(
        name: *const ::std::os::raw::c_char, vptr: *mut *const ::std::os::raw::c_char,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn SCConfGetInt(
        name: *const ::std::os::raw::c_char, val: *mut intmax_t,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn SCConfGetBool(
        name: *const ::std::os::raw::c_char, val: *mut ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn SCConfGetDouble(
        name: *const ::std::os::raw::c_char, val: *mut f64,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn SCConfGetFloat(
        name: *const ::std::os::raw::c_char, val: *mut f32,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn SCConfSet(
        name: *const ::std::os::raw::c_char, val: *const ::std::os::raw::c_char,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn SCConfSetFromString(
        input: *const ::std::os::raw::c_char, final_: ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn SCConfSetFinal(
        name: *const ::std::os::raw::c_char, val: *const ::std::os::raw::c_char,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn SCConfDump();
}
extern "C" {
    pub fn SCConfNodeDump(node: *const SCConfNode, prefix: *const ::std::os::raw::c_char);
}
extern "C" {
    pub fn SCConfNodeNew() -> *mut SCConfNode;
}
extern "C" {
    pub fn SCConfNodeFree(arg1: *mut SCConfNode);
}
extern "C" {
    pub fn SCConfGetNode(key: *const ::std::os::raw::c_char) -> *mut SCConfNode;
}
extern "C" {
    pub fn SCConfCreateContextBackup();
}
extern "C" {
    pub fn SCConfRestoreContextBackup();
}
extern "C" {
    pub fn SCConfNodeLookupChild(
        node: *const SCConfNode, key: *const ::std::os::raw::c_char,
    ) -> *mut SCConfNode;
}
extern "C" {
    pub fn SCConfNodeLookupChildValue(
        node: *const SCConfNode, key: *const ::std::os::raw::c_char,
    ) -> *const ::std::os::raw::c_char;
}
extern "C" {
    pub fn SCConfNodeRemove(arg1: *mut SCConfNode);
}
extern "C" {
    pub fn SCConfRegisterTests();
}
extern "C" {
    pub fn SCConfNodeChildValueIsTrue(
        node: *const SCConfNode, key: *const ::std::os::raw::c_char,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn SCConfValIsTrue(val: *const ::std::os::raw::c_char) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn SCConfValIsFalse(val: *const ::std::os::raw::c_char) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn SCConfNodePrune(node: *mut SCConfNode);
}
extern "C" {
    pub fn SCConfRemove(name: *const ::std::os::raw::c_char) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn SCConfNodeHasChildren(node: *const SCConfNode) -> bool;
}
extern "C" {
    pub fn SCConfGetChildWithDefault(
        base: *const SCConfNode, dflt: *const SCConfNode, name: *const ::std::os::raw::c_char,
    ) -> *mut SCConfNode;
}
extern "C" {
    pub fn SCConfNodeLookupKeyValue(
        base: *const SCConfNode, key: *const ::std::os::raw::c_char,
        value: *const ::std::os::raw::c_char,
    ) -> *mut SCConfNode;
}
extern "C" {
    pub fn SCConfGetChildValue(
        base: *const SCConfNode, name: *const ::std::os::raw::c_char,
        vptr: *mut *const ::std::os::raw::c_char,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn SCConfGetChildValueInt(
        base: *const SCConfNode, name: *const ::std::os::raw::c_char, val: *mut intmax_t,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn SCConfGetChildValueBool(
        base: *const SCConfNode, name: *const ::std::os::raw::c_char,
        val: *mut ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn SCConfGetChildValueWithDefault(
        base: *const SCConfNode, dflt: *const SCConfNode, name: *const ::std::os::raw::c_char,
        vptr: *mut *const ::std::os::raw::c_char,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn SCConfGetChildValueIntWithDefault(
        base: *const SCConfNode, dflt: *const SCConfNode, name: *const ::std::os::raw::c_char,
        val: *mut intmax_t,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn SCConfGetChildValueBoolWithDefault(
        base: *const SCConfNode, dflt: *const SCConfNode, name: *const ::std::os::raw::c_char,
        val: *mut ::std::os::raw::c_int,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn SCConfNodeIsSequence(node: *const SCConfNode) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn SCConfSetIfaceNode(
        ifaces_node_name: *const ::std::os::raw::c_char, iface: *const ::std::os::raw::c_char,
    ) -> *mut SCConfNode;
}
extern "C" {
    pub fn SCConfSetRootAndDefaultNodes(
        ifaces_node_name: *const ::std::os::raw::c_char, iface: *const ::std::os::raw::c_char,
        if_root: *mut *mut SCConfNode, if_default: *mut *mut SCConfNode,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn SCConfNodeGetNodeOrCreate(
        parent: *mut SCConfNode, name: *const ::std::os::raw::c_char, final_: ::std::os::raw::c_int,
    ) -> *mut SCConfNode;
}

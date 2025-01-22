#[repr(u32)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum SCAppLayerEventType {
    APP_LAYER_EVENT_TYPE_TRANSACTION = 1,
    APP_LAYER_EVENT_TYPE_PACKET = 2,
}
pub type SCAppLayerStateGetEventInfoByIdFn = ::std::option::Option<
    unsafe extern "C" fn(
        event_id: u8,
        event_name: *mut *const ::std::os::raw::c_char,
        event_type: *mut SCAppLayerEventType,
    ) -> ::std::os::raw::c_int,
>;
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
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct JsonBuilder {
    _unused: [u8; 0],
}
#[doc = " A \"mark\" or saved state for a JsonBuilder object.\n\n The name is full, and the types are u64 as this object is used\n directly in C as well."]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct JsonBuilderMark {
    pub position: u64,
    pub state_index: u64,
    pub state: u64,
}
#[test]
fn bindgen_test_layout_JsonBuilderMark() {
    const UNINIT: ::std::mem::MaybeUninit<JsonBuilderMark> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<JsonBuilderMark>(),
        24usize,
        "Size of JsonBuilderMark"
    );
    assert_eq!(
        ::std::mem::align_of::<JsonBuilderMark>(),
        8usize,
        "Alignment of JsonBuilderMark"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).position) as usize - ptr as usize },
        0usize,
        "Offset of field: JsonBuilderMark::position"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).state_index) as usize - ptr as usize },
        8usize,
        "Offset of field: JsonBuilderMark::state_index"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).state) as usize - ptr as usize },
        16usize,
        "Offset of field: JsonBuilderMark::state"
    );
}
extern "C" {
    pub fn jb_new_object() -> *mut JsonBuilder;
}
extern "C" {
    pub fn jb_new_array() -> *mut JsonBuilder;
}
extern "C" {
    pub fn jb_clone(js: *mut JsonBuilder) -> *mut JsonBuilder;
}
extern "C" {
    pub fn jb_free(js: *mut JsonBuilder);
}
extern "C" {
    pub fn jb_capacity(jb: *mut JsonBuilder) -> usize;
}
extern "C" {
    pub fn jb_reset(jb: *mut JsonBuilder);
}
extern "C" {
    pub fn jb_open_object(js: *mut JsonBuilder, key: *const ::std::os::raw::c_char) -> bool;
}
extern "C" {
    pub fn jb_start_object(js: *mut JsonBuilder) -> bool;
}
extern "C" {
    pub fn jb_open_array(js: *mut JsonBuilder, key: *const ::std::os::raw::c_char) -> bool;
}
extern "C" {
    pub fn jb_set_string(
        js: *mut JsonBuilder, key: *const ::std::os::raw::c_char,
        val: *const ::std::os::raw::c_char,
    ) -> bool;
}
extern "C" {
    pub fn jb_set_string_from_bytes(
        js: *mut JsonBuilder, key: *const ::std::os::raw::c_char, bytes: *const u8, len: u32,
    ) -> bool;
}
extern "C" {
    pub fn jb_set_base64(
        js: *mut JsonBuilder, key: *const ::std::os::raw::c_char, bytes: *const u8, len: u32,
    ) -> bool;
}
extern "C" {
    pub fn jb_set_hex(
        js: *mut JsonBuilder, key: *const ::std::os::raw::c_char, bytes: *const u8, len: u32,
    ) -> bool;
}
extern "C" {
    pub fn jb_set_formatted(js: *mut JsonBuilder, formatted: *const ::std::os::raw::c_char)
        -> bool;
}
extern "C" {
    pub fn jb_append_object(jb: *mut JsonBuilder, obj: *const JsonBuilder) -> bool;
}
extern "C" {
    pub fn jb_set_object(
        js: *mut JsonBuilder, key: *const ::std::os::raw::c_char, val: *mut JsonBuilder,
    ) -> bool;
}
extern "C" {
    pub fn jb_append_string(js: *mut JsonBuilder, val: *const ::std::os::raw::c_char) -> bool;
}
extern "C" {
    pub fn jb_append_string_from_bytes(js: *mut JsonBuilder, bytes: *const u8, len: u32) -> bool;
}
extern "C" {
    pub fn jb_append_base64(js: *mut JsonBuilder, bytes: *const u8, len: u32) -> bool;
}
extern "C" {
    pub fn jb_append_uint(js: *mut JsonBuilder, val: u64) -> bool;
}
extern "C" {
    pub fn jb_append_float(js: *mut JsonBuilder, val: f64) -> bool;
}
extern "C" {
    pub fn jb_set_uint(js: *mut JsonBuilder, key: *const ::std::os::raw::c_char, val: u64) -> bool;
}
extern "C" {
    pub fn jb_set_int(js: *mut JsonBuilder, key: *const ::std::os::raw::c_char, val: i64) -> bool;
}
extern "C" {
    pub fn jb_set_float(js: *mut JsonBuilder, key: *const ::std::os::raw::c_char, val: f64)
        -> bool;
}
extern "C" {
    pub fn jb_set_bool(js: *mut JsonBuilder, key: *const ::std::os::raw::c_char, val: bool)
        -> bool;
}
extern "C" {
    pub fn jb_close(js: *mut JsonBuilder) -> bool;
}
extern "C" {
    pub fn jb_len(js: *const JsonBuilder) -> usize;
}
extern "C" {
    pub fn jb_ptr(js: *mut JsonBuilder) -> *const u8;
}
extern "C" {
    pub fn jb_get_mark(js: *mut JsonBuilder, mark: *mut JsonBuilderMark);
}
extern "C" {
    pub fn jb_restore_mark(js: *mut JsonBuilder, mark: *mut JsonBuilderMark) -> bool;
}

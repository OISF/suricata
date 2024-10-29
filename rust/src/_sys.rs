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

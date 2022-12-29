// NOTE: if ALPROTO's get >= 256, update SignatureNonPrefilterStore
#[derive(PartialEq, Eq, Clone, Copy, Debug)]
#[repr(u16)]
#[allow(non_camel_case_types)]
pub enum AppProto {
    ALPROTO_UNKNOWN = 0,
    ALPROTO_HTTP1,
    ALPROTO_FTP,
    ALPROTO_SMTP,
    ALPROTO_TLS, /* SSLv2, SSLv3 & TLSv1 */
    ALPROTO_SSH,
    ALPROTO_IMAP,
    ALPROTO_JABBER,
    ALPROTO_SMB,
    ALPROTO_DCERPC,
    ALPROTO_IRC,

    ALPROTO_DNS,
    ALPROTO_MODBUS,
    ALPROTO_ENIP,
    ALPROTO_DNP3,
    ALPROTO_NFS,
    ALPROTO_NTP,
    ALPROTO_FTPDATA,
    ALPROTO_TFTP,
    ALPROTO_IKE,
    ALPROTO_KRB5,
    ALPROTO_QUIC,
    ALPROTO_DHCP,
    ALPROTO_SNMP,
    ALPROTO_SIP,
    ALPROTO_RFB,
    ALPROTO_MQTT,
    ALPROTO_PGSQL,
    ALPROTO_TELNET,
    ALPROTO_TEMPLATE,
    ALPROTO_RDP,
    ALPROTO_HTTP2,
    ALPROTO_BITTORRENT_DHT,

    // signature-only (ie not seen in flow)
    // HTTP for any version (ALPROTO_HTTP1 (version 1) or ALPROTO_HTTP2)
    ALPROTO_HTTP,

    /* used by the probing parser when alproto detection fails
     * permanently for that particular stream */
    ALPROTO_FAILED,

#[cfg(test)]
    ALPROTO_TEST,

    /* keep last */
    ALPROTO_MAX,
}


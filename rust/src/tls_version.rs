use std::borrow::Cow;
use std::ffi::c_char;
use std::ptr;

/* Max string length of the TLS version string */
pub const SSL_VERSION_MAX_STRLEN: usize = 20;

// Enum as constants for C ABI
pub const TLS_VERSION_UNKNOWN: u16 = 0x0000;
pub const SSL_VERSION_2: u16 = 0x0200;
pub const SSL_VERSION_3: u16 = 0x0300;
pub const TLS_VERSION_10: u16 = 0x0301;
pub const TLS_VERSION_11: u16 = 0x0302;
pub const TLS_VERSION_12: u16 = 0x0303;
pub const TLS_VERSION_13: u16 = 0x0304;
pub const TLS_VERSION_13_DRAFT28: u16 = 0x7f1c;
pub const TLS_VERSION_13_DRAFT27: u16 = 0x7f1b;
pub const TLS_VERSION_13_DRAFT26: u16 = 0x7f1a;
pub const TLS_VERSION_13_DRAFT25: u16 = 0x7f19;
pub const TLS_VERSION_13_DRAFT24: u16 = 0x7f18;
pub const TLS_VERSION_13_DRAFT23: u16 = 0x7f17;
pub const TLS_VERSION_13_DRAFT22: u16 = 0x7f16;
pub const TLS_VERSION_13_DRAFT21: u16 = 0x7f15;
pub const TLS_VERSION_13_DRAFT20: u16 = 0x7f14;
pub const TLS_VERSION_13_DRAFT19: u16 = 0x7f13;
pub const TLS_VERSION_13_DRAFT18: u16 = 0x7f12;
pub const TLS_VERSION_13_DRAFT17: u16 = 0x7f11;
pub const TLS_VERSION_13_DRAFT16: u16 = 0x7f10;
pub const TLS_VERSION_13_PRE_DRAFT16: u16 = 0x7f01;
pub const TLS_VERSION_13_DRAFT20_FB: u16 = 0xfb14;
pub const TLS_VERSION_13_DRAFT21_FB: u16 = 0xfb15;
pub const TLS_VERSION_13_DRAFT22_FB: u16 = 0xfb16;
pub const TLS_VERSION_13_DRAFT23_FB: u16 = 0xfb17;
pub const TLS_VERSION_13_DRAFT26_FB: u16 = 0xfb1a;

/* SSL versions.  We'll use a unified format for all, with the top byte
 * holding the major version and the lower byte the minor version */
#[repr(u16)]
#[derive(Default)]
pub enum SCTlsVersion {
    #[default]
    Unknown = TLS_VERSION_UNKNOWN,
    SslV2 = SSL_VERSION_2,
    SslV3 = SSL_VERSION_3,
    TlsV1_0 = TLS_VERSION_10,
    TlsV1_1 = TLS_VERSION_11,
    TlsV1_2 = TLS_VERSION_12,
    TlsV1_3 = TLS_VERSION_13,
    Tls13Draft28 = TLS_VERSION_13_DRAFT28,
    Tls13Draft27 = TLS_VERSION_13_DRAFT27,
    Tls13Draft26 = TLS_VERSION_13_DRAFT26,
    Tls13Draft25 = TLS_VERSION_13_DRAFT25,
    Tls13Draft24 = TLS_VERSION_13_DRAFT24,
    Tls13Draft23 = TLS_VERSION_13_DRAFT23,
    Tls13Draft22 = TLS_VERSION_13_DRAFT22,
    Tls13Draft21 = TLS_VERSION_13_DRAFT21,
    Tls13Draft20 = TLS_VERSION_13_DRAFT20,
    Tls13Draft19 = TLS_VERSION_13_DRAFT19,
    Tls13Draft18 = TLS_VERSION_13_DRAFT18,
    Tls13Draft17 = TLS_VERSION_13_DRAFT17,
    Tls13Draft16 = TLS_VERSION_13_DRAFT16,
    Tls13PreDraft16 = TLS_VERSION_13_PRE_DRAFT16,
    Tls13Draft20Fb = TLS_VERSION_13_DRAFT20_FB,
    Tls13Draft21Fb = TLS_VERSION_13_DRAFT21_FB,
    Tls13Draft22Fb = TLS_VERSION_13_DRAFT22_FB,
    Tls13Draft23Fb = TLS_VERSION_13_DRAFT23_FB,
    Tls13Draft26Fb = TLS_VERSION_13_DRAFT26_FB,
}

impl TryFrom<u16> for SCTlsVersion {
    type Error = ();

    fn try_from(v: u16) -> Result<Self, Self::Error> {
        match v {
            0x0000 => Ok(Self::Unknown),
            0x0200 => Ok(Self::SslV2),
            0x0300 => Ok(Self::SslV3),
            0x0301 => Ok(Self::TlsV1_0),
            0x0302 => Ok(Self::TlsV1_1),
            0x0303 => Ok(Self::TlsV1_2),
            0x0304 => Ok(Self::TlsV1_3),
            0x7f1c => Ok(Self::Tls13Draft28),
            0x7f1b => Ok(Self::Tls13Draft27),
            0x7f1a => Ok(Self::Tls13Draft26),
            0x7f19 => Ok(Self::Tls13Draft25),
            0x7f18 => Ok(Self::Tls13Draft24),
            0x7f17 => Ok(Self::Tls13Draft23),
            0x7f16 => Ok(Self::Tls13Draft22),
            0x7f15 => Ok(Self::Tls13Draft21),
            0x7f14 => Ok(Self::Tls13Draft20),
            0x7f13 => Ok(Self::Tls13Draft19),
            0x7f12 => Ok(Self::Tls13Draft18),
            0x7f11 => Ok(Self::Tls13Draft17),
            0x7f10 => Ok(Self::Tls13Draft16),
            0x7f01 => Ok(Self::Tls13PreDraft16),
            0xfb14 => Ok(Self::Tls13Draft20Fb),
            0xfb15 => Ok(Self::Tls13Draft21Fb),
            0xfb16 => Ok(Self::Tls13Draft22Fb),
            0xfb17 => Ok(Self::Tls13Draft23Fb),
            0xfb1a => Ok(Self::Tls13Draft26Fb),
            _ => Err(()),
        }
    }
}

impl SCTlsVersion {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unknown => "UNDETERMINED",
            Self::SslV2 => "SSLv2",
            Self::SslV3 => "SSLv3",
            Self::TlsV1_0 => "TLSv1",
            Self::TlsV1_1 => "TLS 1.1",
            Self::TlsV1_2 => "TLS 1.2",
            Self::TlsV1_3 => "TLS 1.3",
            Self::Tls13Draft28 => "TLS 1.3 draft-28",
            Self::Tls13Draft27 => "TLS 1.3 draft-27",
            Self::Tls13Draft26 => "TLS 1.3 draft-26",
            Self::Tls13Draft25 => "TLS 1.3 draft-25",
            Self::Tls13Draft24 => "TLS 1.3 draft-24",
            Self::Tls13Draft23 => "TLS 1.3 draft-23",
            Self::Tls13Draft22 => "TLS 1.3 draft-22",
            Self::Tls13Draft21 => "TLS 1.3 draft-21",
            Self::Tls13Draft20 => "TLS 1.3 draft-20",
            Self::Tls13Draft19 => "TLS 1.3 draft-19",
            Self::Tls13Draft18 => "TLS 1.3 draft-18",
            Self::Tls13Draft17 => "TLS 1.3 draft-17",
            Self::Tls13Draft16 => "TLS 1.3 draft-16",
            Self::Tls13PreDraft16 => "TLS 1.3 draft-<16",
            Self::Tls13Draft20Fb => "TLS 1.3 draft-20-fb",
            Self::Tls13Draft21Fb => "TLS 1.3 draft-21-fb",
            Self::Tls13Draft22Fb => "TLS 1.3 draft-22-fb",
            Self::Tls13Draft23Fb => "TLS 1.3 draft-23-fb",
            Self::Tls13Draft26Fb => "TLS 1.3 draft-26-fb",
        }
    }

    fn is_valid(v: u16) -> bool {
        match Self::try_from(v) {
            Ok(SCTlsVersion::Unknown) => false,
            Ok(SCTlsVersion::SslV2) => false,
            Err(_) => false,
            _ => true,
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn TLSVersionValid(v: u16) -> bool {
    SCTlsVersion::is_valid(v)
}

#[no_mangle]
pub unsafe extern "C" fn SSLVersionToString(v: u16, buf: *mut c_char) -> bool {
    let vers = match SCTlsVersion::try_from(v) {
        Ok(val) => Cow::Borrowed(val.as_str()),
        Err(_) => Cow::Owned(v.to_string()),
    };
    let b = vers.as_bytes();

    if b.len() > SSL_VERSION_MAX_STRLEN {
        return false;
    }

    ptr::write_bytes(buf, 0, b.len());
    std::ptr::copy_nonoverlapping(b.as_ptr() as *const c_char, buf, b.len());
    *buf.add(b.len()) = 0;
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_versions() {
        assert!(SCTlsVersion::is_valid(SSL_VERSION_3));
        assert!(SCTlsVersion::is_valid(TLS_VERSION_10));
        assert!(SCTlsVersion::is_valid(TLS_VERSION_11));
        assert!(SCTlsVersion::is_valid(TLS_VERSION_12));
        assert!(SCTlsVersion::is_valid(TLS_VERSION_13_DRAFT16));
    }

    #[test]
    fn test_invalid_versions() {
        assert!(!SCTlsVersion::is_valid(TLS_VERSION_UNKNOWN));
        assert!(!SCTlsVersion::is_valid(SSL_VERSION_2));
    }

    // Out-of-range ie unknown currently
    #[test]
    fn test_oor_versions() {
        assert!(!SCTlsVersion::is_valid(0xffff));
        assert!(!SCTlsVersion::is_valid(0xfffe));
    }
}

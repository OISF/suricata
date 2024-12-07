use crate::suricata::{
    rs_detect_u8_match, rs_detect_u8_parse, DetectBufferSetActiveList,
    DetectHelperBufferMpmRegister, DetectHelperBufferRegister, DetectHelperGetData,
    DetectHelperKeywordRegister, DetectHelperKeywordSetup, DetectSignatureSetAppProto,
    DetectUintData, Level, SCSigTableElmt, SIGMATCH_INFO_STICKY_BUFFER, SIGMATCH_NOOPT,
};
use crate::util::ctor_pointer;
use crate::util::SCLog;
use crate::zabbix::{ZabbixTransaction, ALPROTO_ZABBIX};
use std::os::raw::{c_int, c_void};

#[no_mangle]
pub unsafe extern "C" fn rs_zabbix_keywords_register() {
    SCLog!(Level::Info, "registering Zabbix keywords");
    zabbix_register_flags_keyword();
    zabbix_register_data_keyword();
}

static mut G_ZABBIX_FLAGS_KWID: c_int = 0;
static mut G_ZABBIX_FLAGS_BUFFER_ID: c_int = 0;

#[no_mangle]
pub unsafe extern "C" fn rs_zabbix_flags_setup(
    de: *mut c_void,
    s: *mut c_void,
    raw: *const std::os::raw::c_char,
) -> c_int {
    let ctx = rs_detect_u8_parse(raw) as *mut std::os::raw::c_void;
    if ctx.is_null() {
        return -1;
    }
    let r = DetectHelperKeywordSetup(
        de,
        ALPROTO_ZABBIX,
        G_ZABBIX_FLAGS_KWID,
        G_ZABBIX_FLAGS_BUFFER_ID,
        s,
        ctx,
    );
    if r < 0 {
        rs_zabbix_flags_free(std::ptr::null_mut(), ctx);
    }
    r
}

#[no_mangle]
pub unsafe extern "C" fn rs_zabbix_flags_match(
    _de: *mut c_void,
    _f: *mut c_void,
    _flags: u8,
    _state: *mut c_void,
    tx: *mut c_void,
    _sig: *const c_void,
    ctx: *const c_void,
) -> c_int {
    let tx = ctor_pointer!(tx, ZabbixTransaction);
    rs_detect_u8_match(tx.zabbix.flags, ctx)
}

#[no_mangle]
pub unsafe extern "C" fn rs_zabbix_flags_free(_de: *mut c_void, ctx: *mut c_void) {
    // Just unbox...
    let ctx = ctor_pointer!(ctx, DetectUintData<u8>);
    std::mem::drop(Box::from_raw(ctx));
}

fn zabbix_register_flags_keyword() {
    let kw = SCSigTableElmt {
        name: b"zabbix.flags\0".as_ptr() as *const libc::c_char,
        desc: b"match on zabbix header flags\0".as_ptr() as *const libc::c_char,
        url: b"\0".as_ptr() as *const libc::c_char,
        flags: 0,
        AppLayerTxMatch: Some(rs_zabbix_flags_match),
        Setup: rs_zabbix_flags_setup,
        Free: Some(rs_zabbix_flags_free),
    };
    unsafe {
        G_ZABBIX_FLAGS_KWID = DetectHelperKeywordRegister(&kw);
        G_ZABBIX_FLAGS_BUFFER_ID = DetectHelperBufferRegister(
            b"zabbix_flags\0".as_ptr() as *const libc::c_char,
            ALPROTO_ZABBIX,
            true,
            true,
        );
    }
}

static mut G_ZABBIX_DATA_BUFID: c_int = 0;

#[no_mangle]
pub unsafe extern "C" fn rs_zabbix_data_setup(
    de: *mut c_void,
    s: *mut c_void,
    _raw: *const std::os::raw::c_char,
) -> c_int {
    if DetectBufferSetActiveList(de, s, G_ZABBIX_DATA_BUFID) < 0 {
        return -1;
    }
    if DetectSignatureSetAppProto(s, ALPROTO_ZABBIX) != 0 {
        return -1;
    }

    0
}

#[no_mangle]
pub unsafe extern "C" fn rs_zabbix_data(
    tx: *const c_void,
    _flow_flags: u8,
    buffer: *mut *const u8,
    buffer_len: *mut u32,
) -> bool {
    let tx = ctor_pointer!(tx, ZabbixTransaction);
    *buffer = tx.zabbix.data.as_ptr();
    *buffer_len = tx.zabbix.data.len() as u32;
    true
}

#[no_mangle]
pub unsafe extern "C" fn rs_zabbix_get_data(
    de: *mut c_void,
    transforms: *const c_void,
    flow: *const c_void,
    flow_flags: u8,
    tx: *const c_void,
    list_id: c_int,
) -> *mut c_void {
    DetectHelperGetData(
        de,
        transforms,
        flow,
        flow_flags,
        tx,
        list_id,
        rs_zabbix_data,
    )
}

pub(super) fn zabbix_register_data_keyword() {
    let kw = SCSigTableElmt {
        name: b"zabbix.data\0".as_ptr() as *const libc::c_char,
        desc: b"match on zabbix data\0".as_ptr() as *const libc::c_char,
        url: b"\0".as_ptr() as *const libc::c_char,
        Setup: rs_zabbix_data_setup,
        flags: SIGMATCH_NOOPT | SIGMATCH_INFO_STICKY_BUFFER,
        AppLayerTxMatch: None,
        Free: None,
    };
    unsafe {
        DetectHelperKeywordRegister(&kw);
        G_ZABBIX_DATA_BUFID = DetectHelperBufferMpmRegister(
            b"zabbix_data\0".as_ptr() as *const libc::c_char,
            b"zabbix data\0".as_ptr() as *const libc::c_char,
            ALPROTO_ZABBIX,
            true,
            true,
            rs_zabbix_get_data,
        );
    }
}

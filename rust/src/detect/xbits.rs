use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};

pub const DETECT_XBITS_CMD_SET: u8 = 0;
pub const DETECT_XBITS_CMD_TOGGLE: u8 = 1;
pub const DETECT_XBITS_CMD_UNSET: u8 = 2;
pub const DETECT_XBITS_CMD_ISNOTSET: u8 = 3;
pub const DETECT_XBITS_CMD_ISSET: u8 = 4;
pub const DETECT_XBITS_CMD_NOALERT: u8 = 5;
pub const DETECT_XBITS_CMD_MAX: u8 = 6;
pub const DETECT_XBITS_TRACK_IPSRC: u8 = 0;
pub const DETECT_XBITS_TRACK_IPDST: u8 = 1;
pub const DETECT_XBITS_TRACK_IPPAIR: u8 = 2;
pub const DETECT_XBITS_TRACK_FLOW: u8 = 3;
pub const DETECT_XBITS_EXPIRE_DEFAULT: u32 = 30;

#[repr(C)]
#[derive(Debug)]
pub struct RSXBitsData {
    cmd: u8,
    tracker: u8,
    expire: u32,
    vartype: u8,
    name: *const c_char,
}

fn get_xbit_type(str_t: &str) -> Result<u8, ()> {
    let res = match str_t {
        "ip_src" => DETECT_XBITS_TRACK_IPSRC,
        "ip_dst" => DETECT_XBITS_TRACK_IPDST,
        "ip_pair" => DETECT_XBITS_TRACK_IPPAIR,
        "flow" => DETECT_XBITS_TRACK_FLOW,
        _ => return Err(()),
    };
    Ok(res)
}

fn get_xbit_cmd(str_c: &str) -> Result<u8, ()> {
    let res = match str_c {
        "set" => DETECT_XBITS_CMD_SET,
        "toggle" => DETECT_XBITS_CMD_TOGGLE,
        "unset" => DETECT_XBITS_CMD_UNSET,
        "isnotset" => DETECT_XBITS_CMD_ISNOTSET,
        "isset" => DETECT_XBITS_CMD_ISSET,
        "noalert" => DETECT_XBITS_CMD_NOALERT,
        _ => return Err(()),
    };
    Ok(res)
}

fn evaluate_args(args: Vec<&str>) -> Result<(u8, CString, u8, u32, u8), ()> {
    let tracker: Vec<&str> = args[2].trim().split(' ').collect();
    if tracker.len() != 2 {
        return Err(());
    }
    match tracker[0].trim() {
        "track" => {}
        _ => {
            SCLogError!("xbits track keyword parsing failed");
            return Err(());
        }
    }
    let tracker: u8 = match get_xbit_type(tracker[1].trim()) {
        Ok(val) => val,
        Err(e) => {
            SCLogError!("xbits tracker parsing failed: {:?}", e);
            return Err(());
        }
    };
    let vartype = if tracker == DETECT_XBITS_TRACK_IPPAIR {
        11 // VAR_TYPE_IPPAIR_BIT
    } else {
        8 // VAR_TYPE_HOST_BIT
    };
    let cmd: u8 = match get_xbit_cmd(args[0].trim()) {
        Ok(val) => val,
        Err(_) => {
            SCLogError!("xbits cmd parsing failed");
            return Err(());
        }
    };
    let name = CString::new(args[1].trim()).unwrap();
    if args.len() == 3 {
        return Ok((cmd, name, tracker, DETECT_XBITS_EXPIRE_DEFAULT, vartype));
    }
    let expire: Vec<&str> = args[3].trim().split(' ').collect();
    if expire.len() != 2 {
        return Err(());
    }
    match expire[0].trim() {
        "expire" => {}
        _ => {
            SCLogError!("xbits expire keyword parsing failed");
            return Err(());
        }
    }
    let expire: u32 = match expire[1].trim().parse() {
        Ok(val) => val,
        Err(_) => {
            SCLogError!("xbits expire parsing failed");
            return Err(());
        }
    };
    if expire == 0 {
        return Err(());
    }
    Ok((cmd, name, tracker, expire, vartype))
}

pub fn parse_xbits(arg: &str) -> Result<RSXBitsData, ()> {
    let split_args: Vec<&str> = arg.split(',').collect();
    let res;

    match split_args.len() {
        1 => match split_args[0] {
            "noalert" => {
                return Ok(RSXBitsData {
                    cmd: get_xbit_cmd("noalert")?,
                    name: std::ptr::null_mut(),
                    tracker: 0,
                    expire: 0,
                    vartype: 0,
                })
            }
            _ => {
                SCLogError!("xbits noalert parsing failed");
                return Err(());
            }
        },
        3 | 4 => {
            res = match evaluate_args(split_args) {
                Ok(val) => val,
                Err(_) => return Err(()),
            };
        }
        e => {
            SCLogError!("Erroneous number of arguments: {}", e);
            return Err(());
        }
    }
    Ok(RSXBitsData {
        cmd: res.0,
        name: (res.1).into_raw(),
        tracker: res.2,
        expire: res.3,
        vartype: res.4,
    })
}

#[no_mangle]
pub unsafe extern "C" fn rs_xbits_parse(carg: *const c_char) -> *mut c_void {
    if carg.is_null() {
        return std::ptr::null_mut();
    }

    let arg = match CStr::from_ptr(carg).to_str() {
        Ok(arg) => arg,
        _ => {
            return std::ptr::null_mut();
        }
    };

    match parse_xbits(arg) {
        Ok(detect) => Box::into_raw(Box::new(detect)) as *mut _,
        Err(_) => {
            return std::ptr::null_mut();
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_xbits_free(ptr: *mut c_void, name: *const c_char) {
    if !ptr.is_null() {
        let _str = CString::from_raw(name as *mut c_char);
        std::mem::drop(Box::from_raw(ptr as *mut RSXBitsData));
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_bad_input() {
        assert_eq!(true, parse_xbits("alert").is_err());
        assert_eq!(true, parse_xbits("n0alert").is_err());
        assert_eq!(true, parse_xbits("nOalert").is_err());
        assert_eq!(
            true,
            parse_xbits("set,abc,track nonsense, expire 3600").is_err()
        );
        assert_eq!(
            true,
            parse_xbits("set,abc,track ip_source, expire 3600").is_err()
        );
        assert_eq!(
            true,
            parse_xbits("set,abc,track ip_src, expire -1").is_err()
        );
        assert_eq!(true, parse_xbits("set,abc,track ip_src, expire 0").is_err());
        assert_eq!(
            true,
            parse_xbits("set,abc,expire 1000, track ip_dst").is_err()
        );
        assert_eq!(
            true,
            parse_xbits("set,abc,tracker ip_src, expire 0").is_err()
        );
    }

    #[test]
    fn test_good_input() {
        assert_eq!(true, parse_xbits("noalert").is_ok());
        assert_eq!(true, parse_xbits("set,abc,track ip_pair").is_ok());
        assert_eq!(
            true,
            parse_xbits("set, abc ,track ip_pair, expire 3600").is_ok()
        );
        assert_eq!(
            true,
            parse_xbits("set  ,abc,track ip_src, expire 1234").is_ok()
        );
    }
}

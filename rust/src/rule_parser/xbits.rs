use std::ffi::{CStr, CString};
use std::os::raw::c_char;

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

pub const VAR_TYPE_IPPAIR_BIT: u8 = 11;
pub const VAR_TYPE_HOST_BIT: u8 = 8;

#[repr(C)]
#[derive(Debug)]
pub struct DetectXbitsData {
    idx: u32,
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
    let tracker: Vec<&str> = args[2].trim().split(' ').map(|s| s.trim()).collect();
    if tracker.len() != 2 {
        return Err(());
    }
    if tracker[0].ne("track") {
        SCLogError!("xbits track keyword parsing failed");
        return Err(());
    }
    let tracker: u8 = match get_xbit_type(tracker[1]) {
        Ok(val) => val,
        Err(e) => {
            SCLogError!("xbits tracker parsing failed: {:?}", e);
            return Err(());
        }
    };
    let vartype = if tracker == DETECT_XBITS_TRACK_IPPAIR {
        VAR_TYPE_IPPAIR_BIT
    } else {
        VAR_TYPE_HOST_BIT
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
    let expire: Vec<&str> = args[3].trim().split(' ').map(|s| s.trim()).collect();
    if expire.len() != 2 {
        return Err(());
    }
    if expire[0].ne("expire") {
        SCLogError!("xbits expire keyword parsing failed");
        return Err(());
    }
    let expire: u32 = match expire[1].parse() {
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

fn parse_xbits(arg: &str) -> Result<DetectXbitsData, ()> {
    let split_args: Vec<&str> = arg.trim().split(',').collect();
    let res;

    match split_args.len() {
        1 => match split_args[0] {
            "noalert" => {
                return Ok(DetectXbitsData {
                    idx: 0,  // TODO is this a right thing to do?
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
    Ok(DetectXbitsData {
        idx: 0,
        cmd: res.0,
        name: (res.1).into_raw(),
        tracker: res.2,
        expire: res.3,
        vartype: res.4,
    })
}

impl Drop for DetectXbitsData {
    fn drop(&mut self) {
        if !self.name.is_null() {
            unsafe {
                let _str = CString::from_raw(self.name as *mut c_char);
            }
        }
    }
}

#[no_mangle]
pub unsafe extern "C" fn rs_xbits_parse(carg: *const c_char) -> *mut DetectXbitsData {
    if carg.is_null() {
        return std::ptr::null_mut();
    }

    if let Ok(arg) = CStr::from_ptr(carg).to_str() {
        if let Ok(detect) = parse_xbits(arg) {
            return Box::into_raw(Box::new(detect)) as *mut _;
        }
    }
    std::ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn rs_xbits_free(ptr: *mut DetectXbitsData) {
    if !ptr.is_null() {
        let _xbdata = Box::from_raw(ptr);
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
        let test_str1 = "set, abc ,track ip_pair, expire 3600";
        let test_res1 = parse_xbits(test_str1).unwrap();
        assert_eq!(DETECT_XBITS_CMD_SET, test_res1.cmd);
        assert_eq!(DETECT_XBITS_TRACK_IPPAIR, test_res1.tracker);
        assert_eq!(3600, test_res1.expire);
        assert_eq!(VAR_TYPE_IPPAIR_BIT, test_res1.vartype);
        let test_str2 = "isset  ,abc,track ip_src, expire 1234";
        let test_res2 = parse_xbits(test_str2).unwrap();
        assert_eq!(DETECT_XBITS_CMD_ISSET, test_res2.cmd);
        assert_eq!(DETECT_XBITS_TRACK_IPSRC, test_res2.tracker);
        assert_eq!(1234, test_res2.expire);
        assert_eq!(VAR_TYPE_HOST_BIT, test_res2.vartype);
    }
}

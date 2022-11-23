use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use crate::cast_pointer;

pub const DETECT_BITS_CMD_SET: u8 = 0;
pub const DETECT_BITS_CMD_TOGGLE: u8 = 1;
pub const DETECT_BITS_CMD_UNSET: u8 = 2;
pub const DETECT_BITS_CMD_ISNOTSET: u8 = 3;
pub const DETECT_BITS_CMD_ISSET: u8 = 4;
pub const DETECT_BITS_CMD_NOALERT: u8 = 5;
pub const DETECT_BITS_CMD_MAX: u8 = 6;
pub const DETECT_XBITS_TRACK_IPSRC: u8 = 0;
pub const DETECT_XBITS_TRACK_IPDST: u8 = 1;
pub const DETECT_XBITS_TRACK_IPPAIR: u8 = 2;
pub const DETECT_XBITS_TRACK_FLOW: u8 = 3;
pub const DETECT_XBITS_EXPIRE_DEFAULT: u32 = 30;

pub const VAR_TYPE_IPPAIR_BIT: u8 = 11;
pub const VAR_TYPE_HOST_BIT: u8 = 8;
pub const VAR_TYPE_FLOW_BIT: u8 = 5;

pub const BIT_TYPE_XBIT: u8 = 0;
pub const BIT_TYPE_FLOWBIT: u8 = 1;
pub const BIT_TYPE_HOSTBIT: u8 = 2;


#[derive(Debug)]
pub struct DetectBitsData {
    idx: u32,
    cmd: u8,
    tracker: u8,
    expire: u32,
    vartype: u8,
    name: Option<CString>,
    fb_names: Vec<CString>,
    or_list: Vec<u32>,
    or_list_size: u8,
}

fn get_bit_type_str(bit_type: u8) -> Result<String, ()> {
    let res = match bit_type {
        BIT_TYPE_XBIT => "xbit",
        BIT_TYPE_FLOWBIT => "flowbit",
        BIT_TYPE_HOSTBIT => "hostbit",
        _ => return Err(()),
    };
    Ok(res.to_string())
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

fn get_bit_cmd(str_c: &str) -> Result<u8, ()> {
    let res = match str_c {
        "set" => DETECT_BITS_CMD_SET,
        "toggle" => DETECT_BITS_CMD_TOGGLE,
        "unset" => DETECT_BITS_CMD_UNSET,
        "isnotset" => DETECT_BITS_CMD_ISNOTSET,
        "isset" => DETECT_BITS_CMD_ISSET,
        "noalert" => DETECT_BITS_CMD_NOALERT,
        _ => return Err(()),
    };
    Ok(res)
}

fn parse_cmd_name(args: Vec<&str>, bit_type: u8) -> Result<(u8, CString, Vec<CString>, u8), ()> {
    if args.len() < 2 {
        println!("cmd name parsing issue, args: {:#?}", args);
        return Err(());
    }
    let cmd: u8 = match get_bit_cmd(args[0].trim()) {
        Ok(val) => val,
        Err(_) => {
            SCLogError!("cmd parsing failed");
            return Err(());
        }
    };
    let mut fb_names = vec![];
    if bit_type == BIT_TYPE_FLOWBIT {
        let or_op = args[1].find("|");
        if or_op.is_some() == true {
            fb_names = args[1].split("|")
                .map(|x| CString::new(x).unwrap())
                .collect();
        }
    }
    let fb_len = fb_names.len();
    SCLogNotice!("fb_names: {:#?}", fb_names);
    let name = CString::new(args[1].trim()).unwrap();
    return Ok((cmd, name, fb_names, fb_len as u8));
}

fn evaluate_args(args: Vec<&str>, bit_type: u8) -> Result<(u8, u32, u8), ()> {
    let tracker: Vec<&str> = args[0].trim().split(' ').map(|s| s.trim()).collect();
    if tracker.len() != 2 {
        println!("tracker parsing issue");
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
    println!("tracker: {}", tracker);
    let vartype = if tracker == DETECT_XBITS_TRACK_IPPAIR {
        if bit_type == BIT_TYPE_HOSTBIT {
            return Err(());
        }
        VAR_TYPE_IPPAIR_BIT
    } else {
        VAR_TYPE_HOST_BIT
    };
    println!("vartype: {}", vartype);
    if args.len() == 1 {
        return Ok((tracker, DETECT_XBITS_EXPIRE_DEFAULT, vartype));
    }
    let expire: Vec<&str> = args[1].trim().split(' ').map(|s| s.trim()).collect();
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
    println!("expire: {}", expire);
    if expire == 0 {
        return Err(());
    }
    Ok((tracker, expire, vartype))
}

fn parse_xbits(arg: &str, bit_type: u8) -> Result<DetectBitsData, ()> {
    let split_args: Vec<&str> = arg.trim().split(',').collect();
    let res;
    let cmd_name;

    match split_args.len() {
        1 => match split_args[0] {
            "noalert" => {
                return Ok(DetectBitsData {
                    idx: 0,  // TODO is this a right thing to do?
                    cmd: get_bit_cmd("noalert")?,
                    name: None,
                    tracker: 0,
                    expire: 0,
                    vartype: 0,
                    fb_names: vec![],
                    or_list: vec![],
                    or_list_size: 0,
                })
            }
            _ => {
                SCLogError!("{:?} noalert parsing failed", get_bit_type_str(bit_type));
                return Err(());
            }
        },
        2 => {
            if bit_type != BIT_TYPE_FLOWBIT {
                SCLogError!("Erroneous number of arguments for {:?}", get_bit_type_str(bit_type));
            }
            cmd_name = match parse_cmd_name(split_args.clone(), bit_type) {
                Ok(val) => val,
                Err(_) => return Err(()),
            };
            return Ok(DetectBitsData {
                idx: 0,
                cmd: cmd_name.0,
                name: Some(cmd_name.1),
                tracker: 0,
                expire: 0,
                vartype: VAR_TYPE_FLOW_BIT,
                fb_names: cmd_name.2,
                or_list: vec![],
                or_list_size: cmd_name.3,
            });
        }
        3 | 4 => {
            cmd_name = match parse_cmd_name((&split_args[..2]).to_vec(), bit_type) {
                Ok(val) => val,
                Err(_) => return Err(()),
            };
            res = match evaluate_args((&split_args[2..]).to_vec(), bit_type) {
                Ok(val) => val,
                Err(_) => return Err(()),
            };
        }
        e => {
            SCLogError!("Erroneous number of arguments: {}", e);
            return Err(());
        }
    }
    Ok(DetectBitsData {
        idx: 0,
        cmd: cmd_name.0,
        name: Some(cmd_name.1),
        tracker: res.0,
        expire: res.1,
        vartype: res.2,
        fb_names: vec![],
        or_list: vec![],
        or_list_size: 0,
    })
}

//impl Drop for DetectBitsData {
//    fn drop(&mut self) {
//        unsafe {
//            let fb_names = Vec::from_raw_parts(self.fb_names, self.or_list_size as usize, (2 * self.or_list_size) as usize); // TODO is the capacity gonna be a problem
//            for name in fb_names {
//                let _name = name;
//            }
//        }
//    }
//}

#[no_mangle]
pub unsafe extern "C" fn rs_xbits_get_name(dbd: *const std::os::raw::c_void) -> *const c_char {
    let dbd = cast_pointer!(dbd, DetectBitsData);
    if let Some(name) = &dbd.name {
        return name.as_c_str().as_ptr();
    }
    std::ptr::null()
}

#[no_mangle]
pub unsafe extern "C" fn rs_xbits_get_or_list_idx(dbd: *const std::os::raw::c_void, i: usize) -> u32 {
    let dbd = cast_pointer!(dbd, DetectBitsData);
    dbd.or_list[i]
}

#[no_mangle]
pub unsafe extern "C" fn rs_xbits_get_or_list_item(dbd: *const std::os::raw::c_void, i: usize) -> *const c_char {
    let dbd = cast_pointer!(dbd, DetectBitsData);
    dbd.fb_names[i].as_c_str().as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn rs_xbits_set_or_list_id_at(dbd: *mut std::os::raw::c_void, i: usize, val: u32) {
    let dbd = cast_pointer!(dbd, DetectBitsData);
    dbd.or_list[i] = val;
}

#[no_mangle]
pub unsafe extern "C" fn rs_xbits_set_idx(dbd: *mut std::os::raw::c_void, idx: u32) {
    let dbd = cast_pointer!(dbd, DetectBitsData);
    dbd.idx = idx;
}

#[no_mangle]
pub unsafe extern "C" fn rs_xbits_get_idx(dbd: *const std::os::raw::c_void) -> u32 {
    let dbd = cast_pointer!(dbd, DetectBitsData);
    dbd.idx
}

#[no_mangle]
pub unsafe extern "C" fn rs_xbits_get_expire(dbd: *const std::os::raw::c_void) -> u32 {
    let dbd = cast_pointer!(dbd, DetectBitsData);
    dbd.expire
}

#[no_mangle]
pub unsafe extern "C" fn rs_xbits_get_tracker(dbd: *const std::os::raw::c_void) -> u8 {
    let dbd = cast_pointer!(dbd, DetectBitsData);
    dbd.tracker
}

#[no_mangle]
pub unsafe extern "C" fn rs_xbits_get_cmd(dbd: *const std::os::raw::c_void) -> u8 {
    let dbd = cast_pointer!(dbd, DetectBitsData);
    dbd.cmd
}

#[no_mangle]
pub unsafe extern "C" fn rs_xbits_get_vartype(dbd: *const std::os::raw::c_void) -> u8 {
    let dbd = cast_pointer!(dbd, DetectBitsData);
    dbd.vartype
}

#[no_mangle]
pub unsafe extern "C" fn rs_xbits_get_or_list_size(dbd: *const std::os::raw::c_void) -> u8 {
    let dbd = cast_pointer!(dbd, DetectBitsData);
    dbd.or_list_size
}

#[no_mangle]
pub unsafe extern "C" fn rs_xbits_parse(carg: *const c_char, bit_type: u8) -> *const std::os::raw::c_void {
    if carg.is_null() {
        return std::ptr::null_mut();
    }

    if let Ok(arg) = CStr::from_ptr(carg).to_str() {
        if let Ok(detect) = parse_xbits(arg, bit_type) {
            return Box::into_raw(Box::new(detect)) as *mut _;
        }
    }
    std::ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn rs_bits_free(ptr: *mut std::os::raw::c_void) {
    if !ptr.is_null() {
        let _xbdata = Box::from_raw(ptr);
   }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_bad_input() {
        assert_eq!(true, parse_xbits("alert", 0).is_err());
        assert_eq!(true, parse_xbits("n0alert", 0).is_err());
        assert_eq!(true, parse_xbits("nOalert", 0).is_err());
        assert_eq!(
            true,
            parse_xbits("set,abc,track nonsense, expire 3600", 0).is_err()
        );
        assert_eq!(
            true,
            parse_xbits("set,abc,track ip_source, expire 3600", 0).is_err()
        );
        assert_eq!(
            true,
            parse_xbits("set,abc,track ip_src, expire -1", 0).is_err()
        );
        assert_eq!(true, parse_xbits("set,abc,track ip_src, expire 0", 0).is_err());
        assert_eq!(
            true,
            parse_xbits("set,abc,expire 1000, track ip_dst", 0).is_err()
        );
        assert_eq!(
            true,
            parse_xbits("set,abc,tracker ip_src, expire 0", 0).is_err()
        );
    }

    #[test]
    fn test_good_input() {
        assert_eq!(true, parse_xbits("noalert", 0).is_ok());
        let test_str1 = "set, abc ,track ip_pair, expire 3600";
        let test_res1 = parse_xbits(test_str1, 0).unwrap();
        assert_eq!(DETECT_BITS_CMD_SET, test_res1.cmd);
        assert_eq!(DETECT_XBITS_TRACK_IPPAIR, test_res1.tracker);
        assert_eq!(3600, test_res1.expire);
        assert_eq!(VAR_TYPE_IPPAIR_BIT, test_res1.vartype);
        let test_str2 = "isset  ,abc,track ip_src, expire 1234";
        let test_res2 = parse_xbits(test_str2, 0).unwrap();
        assert_eq!(DETECT_BITS_CMD_ISSET, test_res2.cmd);
        assert_eq!(DETECT_XBITS_TRACK_IPSRC, test_res2.tracker);
        assert_eq!(1234, test_res2.expire);
        assert_eq!(VAR_TYPE_HOST_BIT, test_res2.vartype);
    }
}

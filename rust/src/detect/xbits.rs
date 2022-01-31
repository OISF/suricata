use std::ffi::CStr;
use std::os::raw::{c_char, c_void};


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
        "ip_src" => { 0 },
        "ip_dst" => { 1 },
        "ip_pair" => { 2 },
        "flow" => { 3 },
        _ => { return Err(()) }
    };
    Ok(res)
}

fn get_xbit_cmd(str_c: &str) -> Result<u8, ()> {
    let res = match str_c {
        "set" => { 0 },
        "toggle" => { 1 },
        "unset" => { 2 },
        "isnotset" => { 3 },
        "isset" => { 4 },
        "noalert" => { 5 },
        _ => { return Err(()) }
    };
    Ok(res)
}

fn evaluate_args(args: Vec<&str>) -> Result<(u8, String, u8, u32, u8), ()>
{
    let tracker: Vec<&str> = args[2].split(' ').collect();
    if tracker.len() != 2 {
        return Err(());
    }
    let tracker: u8 = match get_xbit_type(tracker[1]) {
        Ok(val) => { val },
        Err(e) => { SCLogError!("xbits tracker parsing failed: {:?}", e); return Err(()); }
    };
    let vartype = if tracker == 2 {
        11
    } else {
        8
    };
    let cmd: u8 = match get_xbit_cmd(args[0]) {
        Ok(val) => { val },
        Err(_) => { SCLogError!("xbits cmd parsing failed"); return Err(()); }
    };
    let name = args[1].to_string();
    if args.len() == 3 {
        return Ok((cmd, name, tracker, 30, vartype)); // TODO add constants
    }
    let expire: Vec<&str> = args[3].trim().split(' ').collect();
    if expire.len() != 2 {
        return Err(());
    }
    let expire: u32 = match expire[1].parse() {
        Ok(val) => { val },
        Err(_) => { SCLogError!("xbits expire parsing failed"); return Err(()) }
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
        3 | 4 => {
            res = match evaluate_args(split_args) {
                Ok(val) => { val },
                Err(_) => { return Err(()) }
            };
        },
        e => {
            SCLogError!("Erroneous number of arguments: {}", e);
            return Err(());
        }
    }
    println!("res: {:?}", res);
    Ok(RSXBitsData {
        cmd: res.0,
        tracker: res.2,
        expire: res.3,
        vartype: res.4,
//        name: name,
        name: (res.1).as_ptr() as *const std::os::raw::c_char,
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
        Err(_) => std::ptr::null_mut(),
    }
}


#[no_mangle]
pub unsafe extern "C" fn rs_xbits_free(ptr: *mut c_void) {
    if !ptr.is_null() {
        std::mem::drop(Box::from_raw(ptr as *mut RSXBitsData));
    }
}

#[cfg(test)]
mod test {
    use super:: *;

    #[test]
    fn test_bad_input() {
        assert_eq!(true, parse_xbits("alert").is_err());
        assert_eq!(true, parse_xbits("n0alert").is_err());
        assert_eq!(true, parse_xbits("nOalert").is_err());
        assert_eq!(true, parse_xbits("set,abc,track nonsense, expire 3600").is_err());
        assert_eq!(true, parse_xbits("set,abc,track ip_source, expire 3600").is_err());
        assert_eq!(true, parse_xbits("set,abc,track ip_src, expire -1").is_err());
        assert_eq!(true, parse_xbits("set,abc,track ip_src, expire 0").is_err());
    }

    #[test]
    fn test_good_input() {
        assert_eq!(true, parse_xbits("set,abc,track ip_pair").is_ok());
        assert_eq!(true, parse_xbits("set,abc,track ip_pair, expire 3600").is_ok());
        assert_eq!(true, parse_xbits("set,abc,track ip_src, expire 1234").is_ok());
    }

}

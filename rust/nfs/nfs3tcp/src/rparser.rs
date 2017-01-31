//! common functions for all parsers
use common::*;
use filecontainer::*;

/// Interface of all Rusticata parsers.
///
/// A object implementing the RParser trait is an instance of a parser,
/// including the state (and all associated variables).
pub trait RParser {
    // XXX static functions seem to cause problems with hashmaps
    // fn probe(&[u8]) -> bool;

    /// Parsing function
    ///
    /// This function is called for every packet of a connection.
    ///
    /// Arguments:
    ///
    /// - `self`: the state (parser instance)
    /// - a slice on the packet data
    /// - the direction of this packet (0: to server, 1: to client)
    ///
    /// Return value:
    ///
    /// `R_STATUS_OK` or `R_STATUS_FAIL`, possibly or'ed with
    /// `R_STATUS_EVENTS` if parsing events were raised.
    fn parse(&mut self, &[u8], u8) -> u32;

    fn getfiles(&mut self, u8) -> * mut SuricataFileContainer;

    fn setfileflags(&mut self, u8, u16);
}

// status: return code, events

pub static R_STATUS_EVENTS : u32  = 0x0100;

pub static R_STATUS_OK : u32      = 0x0000;
pub static R_STATUS_FAIL : u32    = 0x0001;

pub static R_STATUS_EV_MASK : u32 = 0x0f00;
pub static R_STATUS_MASK : u32    = 0x00ff;

macro_rules! r_status_is_ok {
    ($status:expr) => { ($status & $crate::R_STATUS_MASK) == $crate::R_STATUS_MASK }
}

macro_rules! r_status_has_events {
    ($status:expr) => { ($status & $crate::R_STATUS_EV_MASK) == $crate::R_STATUS_EVENTS }
}

// Helper macros
// We can't define them (can we ?) in the trait, partly because of the 'no_mangle' and 'extern'
// stuff.
// This forces to use macros in addition to the trait, but at least provides a proper way of
// encapsulating the translation of C variables to rust.
/*
macro_rules! r_declare_state_new {
    ($f:ident, $ty:ident, $args:expr) => {
        #[no_mangle]
        pub extern "C" fn $f() -> *mut libc::c_char {
            let b = Box::new($ty::new($args));
            unsafe { mem::transmute(b) }
        }
    }
}*/

macro_rules! r_declare_state_free {
    ($f:ident, $ty:ident, $expr:expr) => {
        impl Drop for $ty{
//        impl<'a> Drop for $ty<'a> {
            fn drop(&mut self) {
                $expr
            }
        }
#[no_mangle]
        pub extern fn $f(ptr: *mut libc::c_char)
        {
            let b: Box<$ty> = unsafe { mem::transmute(ptr) };
            // reference will be dropped automatically, and allocated memory
            // will be freed
            // but let's do it explicitly
            drop(b);
        }
    }
}

/*
macro_rules! r_declare_state_free {
    ($f:ident, $ty:ident, $expr:expr) => {
        impl<'a> Drop for $ty<'a> {
            fn drop(&mut self) {
                $expr
            }
        }

        #[no_mangle]
        pub extern fn $f(ptr: *mut libc::c_char)
        {
            let b: Box<$ty> = unsafe { mem::transmute(ptr) };
            // reference will be dropped automatically, and allocated memory
            // will be freed
            // but let's do it explicitly
            drop(b);
        }
    }
}
*/
macro_rules! r_declare_state_new {
    ($f:ident, $ty:ident, $args:expr) => {
        #[no_mangle]
        pub extern "C" fn $f() -> *mut libc::c_char {
            let b = Box::new($ty::new($args));
            unsafe { mem::transmute(b) }
        }
    };
    ($f:ident, $ty:ident) => {
        #[no_mangle]
        pub extern "C" fn $f() -> *mut libc::c_char {
            let b = Box::new($ty::new());
            unsafe { mem::transmute(b) }
        }
    }
}


macro_rules! r_implement_probe {
    ($f:ident, $g:ident) => {
        #[no_mangle]
        pub extern "C" fn $f(input: *const c_char, input_len: u32, _offset: *const c_char) -> u32 {
            let data_len = input_len as usize;
            let data : &[u8] = unsafe { std::slice::from_raw_parts(input as *mut u8, data_len) };
            match $g(data) {
                true  => 1,
                false => 0,
            }
        }
    }
}

macro_rules! r_implement_parse {
    ($f:ident, $g:ident) => {
        #[no_mangle]
        pub extern "C" fn $f(direction: u8, input: *const c_char, input_len: u32, ptr: *mut $g) -> u32 {
            let data_len = input_len as usize;
            let data : &[u8] = unsafe { std::slice::from_raw_parts(input as *mut u8, data_len) };
            if ptr.is_null() { return 0xffff; };
            let parser = unsafe { &mut *ptr };
            parser.parse(data, direction)
        }
    }
}

macro_rules! r_implement_getfiles {
    ($f:ident, $g:ident) => {
        #[no_mangle]
        pub extern "C" fn $f(direction: u8, ptr: *mut $g) -> &SuricataFileContainer {
            if ptr.is_null() { panic!("NULL ptr"); };
            let parser = unsafe { &mut *ptr };
            parser.getfiles(direction)
        }
    }
}


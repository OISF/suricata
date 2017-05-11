use std::ffi::CString;

pub type LogCallback = extern "C" fn (lvl: u32, file: *const i8, line: u32, func: *const i8, err: u32, msg: *const i8);
// 
// static RAW_LOG : *mut LogCallback = ||{};
// 
// #[macro_export]
// macro_rules! SCLogMessage (
//   ($lvl:expr, $msg:expr) => (
//     {
//         unsafe {  }
//     }
//   );
//   ($lvl:expr, $msg:expr) => (
//     SCLogMessage!($i, $cond, $err);
//   );
// );

#[repr(C)]
pub struct SuricataConfig {
    pub magic: u32,
    pub log: LogCallback,
    pub log_level: i32,
    // other members
}

pub static mut suricata_config : Option<&'static SuricataConfig> = None;

pub fn raw_sclog_message<'a,'b>(lvl: u32, msg: &'a str, file: &'b str, line: u32) {
    match unsafe{suricata_config} {
        None => println!("({}:{}) [{}]: {}", file, line, lvl, msg),
        Some(c) => {
            let c_msg = CString::new(msg).unwrap();
            let c_file = CString::new(file).unwrap();
            let c_func = CString::new("<rust function>").unwrap();

            (c.log)(lvl, c_file.as_ptr(), line, c_func.as_ptr(), 0, c_msg.as_ptr());
        },
    };
}

/// Send a log message to suricata, using the provided log level, message, file and line number
#[macro_export]
macro_rules! SCLogMessage (
  ($lvl:expr, $msg:expr, $file:expr, $line:expr) => (
    {
        $crate::raw_sclog_message($lvl,$msg, $file, $line)
    }
  );
  ($lvl:expr, $msg:expr) => (
    SCLogMessage!($lvl, $msg, file!(), line!());
  );
);

/// Send a log message to suricata, using the Alert severity
#[macro_export]
macro_rules! SCLogAlert (
  ($msg:expr) => ( { SCLogMessage!(2,$msg); });
  ($msg:expr) => ( SCLogAlert!($msg););
);

/// Send a log message to suricata, using the Error severity
#[macro_export]
macro_rules! SCLogError (
  ($msg:expr) => ( { SCLogMessage!(4,$msg); });
  ($msg:expr) => ( SCLogError!($msg););
);

/// Send a log message to suricata, using the Warning severity
#[macro_export]
macro_rules! SCLogWarning (
  ($msg:expr) => ( { SCLogMessage!(5,$msg); });
  ($msg:expr) => ( SCLogWarning!($msg););
);

/// Send a log message to suricata, using the Notice severity
#[macro_export]
macro_rules! SCLogNotice (
  ($msg:expr) => ( { SCLogMessage!(6,$msg); });
  ($msg:expr) => ( SCLogNotice!($msg););
);

/// Send a log message to suricata, using the Info severity
#[macro_export]
macro_rules! SCLogInfo (
  ($msg:expr) => ( { SCLogMessage!(7,$msg); });
  ($msg:expr) => ( SCLogInfo!($msg););
);

/// Send a log message to suricata, using the Debug severity
#[macro_export]
macro_rules! SCLogDebug (
  ($msg:expr) => ( { SCLogMessage!(10,$msg); });
  ($msg:expr) => ( SCLogDebug!($msg););
);



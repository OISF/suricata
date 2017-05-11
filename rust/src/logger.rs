extern crate log;

use log::{LogRecord, LogLevel, LogLevelFilter, LogMetadata, SetLoggerError};

struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &LogMetadata) -> bool {
        metadata.level() <= LogLevel::Debug
    }

    fn log(&self, record: &LogRecord) {
        // if self.enabled(record.metadata()) {
        //     println!("{} - {}", record.level(), record.args());
        // }
        let file = record.location().file();
        let line = record.location().line();
        match record.level() {
            LogLevel::Trace => SCLogMessage!(10,format!("{}",record.args()).as_str(),file,line),
            LogLevel::Debug => SCLogMessage!(10,format!("{}",record.args()).as_str(),file,line),
            LogLevel::Info  => SCLogMessage!(7, format!("{}",record.args()).as_str(),file,line),
            LogLevel::Warn  => SCLogMessage!(5, format!("{}",record.args()).as_str(),file,line),
            LogLevel::Error => SCLogMessage!(4, format!("{}",record.args()).as_str(),file,line),
        }
    }
}

pub fn init(max_level: LogLevelFilter) -> Result<(), SetLoggerError> {
    log::set_logger(|max_log_level| {
        max_log_level.set(max_level);
        Box::new(SimpleLogger)
    })
}

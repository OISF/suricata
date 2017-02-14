// written by Victor Julien
extern crate libc;
use std::ptr;
use common::*;
use std::collections::HashMap;
use filecontainer::*;

macro_rules! println_debug(
    ($($arg:tt)*) => { {
        //println!($($arg)*);
    } }
);


pub struct FileTransferTracker {
    file_size: u64,
    tracked: u64,

    chunk_left: u32,
    fill_bytes: u8,
    file_open: bool,
    chunk_is_last: bool,
    chunk_is_ooo: bool,
    flags: u16,
    chunks: HashMap<u64, Vec<u8>>,
    cur_ooo_chunk_offset: u64,

    pub files: SuricataFileContainer,
}

impl FileTransferTracker {
    pub fn new() -> FileTransferTracker {
        FileTransferTracker {
            file_size:0,
            tracked:0,
            chunk_left:0,
            fill_bytes:0,
            file_open:false,
            chunk_is_last:false,
            chunk_is_ooo:false,
            flags:0,
            cur_ooo_chunk_offset:0,
            chunks:HashMap::new(),
            files:SuricataFileContainer::default(),
        }
    }

    pub fn set_flags(&mut self, flags: u16) {
        self.flags = flags;
        println_debug!("FILE {:p} flags now {:04X}", &self, self.flags);
    }

    fn open(&mut self, name: &[u8]) -> i32 {
        let r = self.files.file_open(name, self.flags);
        self.file_open = true;
        r
    }

    pub fn close(&mut self) {
        self.files.file_close(self.flags);
        self.file_open = false;
        self.tracked = 0;
        self.files.files_prune();
    }

    pub fn create(&mut self, name: &[u8], file_size: u64) {
        if self.file_open == true { panic!("close existing file first"); }

        println_debug!("CREATE: name {:?} file_size {}", name, file_size);
    }

    pub fn new_chunk(&mut self, name: &[u8], data: &[u8], chunk_offset: u64, chunk_size: u32, fill_bytes: u8, is_last: bool) -> u32 {
        if self.chunk_left != 0 { panic!("complete existing chunk first"); }
        if self.fill_bytes != 0 { panic!("complete existing fill bytes first"); }

        println_debug!("NEW CHUNK: chunk_size {} fill_bytes {}", chunk_size, fill_bytes);

        if chunk_offset != self.tracked {
            println_debug!("NEW CHUNK IS OOO: expected {}, got {}", self.tracked, chunk_offset);
            self.chunk_is_ooo = true;
            self.cur_ooo_chunk_offset = chunk_offset;
        }

        self.chunk_left = chunk_size;
        self.fill_bytes = fill_bytes;
        self.chunk_is_last = is_last;

        if self.file_open == false {
            println_debug!("NEW CHUNK: FILE OPEN");
            self.open(name);
        }

        let res = self.update(data);
        println_debug!("NEW CHUNK: update res {:?}", res);
        res
    }

    /// return how much we consumed of data
    pub fn update(&mut self, data: &[u8]) -> u32 {
        let mut consumed = 0 as usize;
        if self.chunk_left + self.fill_bytes as u32 == 0 {
            //println_debug!("UPDATE: nothing to do");
            return 0
        } else if self.chunk_left == 0 {
            println_debug!("FILL BYTES {} from prev run", self.fill_bytes);
            if data.len() >= self.fill_bytes as usize {
                consumed += self.fill_bytes as usize;
                self.fill_bytes = 0;
                println_debug!("CHUNK(pre) fill bytes now 0");
            } else {
                consumed += data.len();
                self.fill_bytes -= data.len() as u8;
                println_debug!("CHUNK(pre) fill bytes now still {}", self.fill_bytes);
            }
            println_debug!("FILL BYTES: returning {}", consumed);
            return consumed as u32
        }
        println_debug!("UPDATE: data {} chunk_left {}", data.len(), self.chunk_left);

        if self.chunk_left > 0 {
            if self.chunk_left <= data.len() as u32 {
                let d = &data[0..self.chunk_left as usize];

                if self.chunk_is_ooo == false {
                    let res = self.files.file_append(d);
                    if res != 0 { panic!("append failed"); }

                    self.tracked += self.chunk_left as u64;
                } else {
                    //println_debug!("UPDATE: appending data {} to cur_ooo_chunk", data.len());
                    println_debug!("UPDATE: appending data {} to ooo chunk at offset {}/{}", d.len(), self.cur_ooo_chunk_offset, self.tracked);

                    // look up existing chunk (if any) and add our data to it
                    // TODO figure out how to do this w/o remove/insert
                    match self.chunks.remove(&self.cur_ooo_chunk_offset) {
                        Some(mut v) => {
                            v.extend(d);
                            println_debug!("UPDATE OOO d {} v {}", d.len(), v.len());
                            self.chunks.insert(self.cur_ooo_chunk_offset, v);
                        },
                        None => {
                            let mut v = Vec::with_capacity(32768); // TODO base on something
                            v.extend(d);
                            self.chunks.insert(self.cur_ooo_chunk_offset, v);
                        },
                    }
                }

                consumed += self.chunk_left as usize;
                if self.fill_bytes > 0 {
                    let extra = data.len() - self.chunk_left as usize;
                    if extra >= self.fill_bytes as usize {
                        consumed += self.fill_bytes as usize;
                        self.fill_bytes = 0;
                        println_debug!("CHUNK(post) fill bytes now 0");
                    } else {
                        consumed += extra;
                        self.fill_bytes -= extra as u8;
                        println_debug!("CHUNK(post) fill bytes now still {}", self.fill_bytes);
                    }
                    self.chunk_left = 0;
                    //return consumed as u32
                } else {
                    self.chunk_left = 0;

                    if self.chunk_is_ooo == false {
                        loop {
                            let offset = self.tracked;
                            match self.chunks.remove(&self.tracked) {
                                Some(a) => {
                                    let res = self.files.file_append(&a);
                                    if res != 0 { panic!("append failed"); }

                                    self.tracked += a.len() as u64;

                                    println_debug!("STORED OOO CHUNK at offset {}, tracked now {}, stored len {}", offset, self.tracked, a.len());
                                },
                                _ => { 
                                    println_debug!("NO STORED CHUNK found at offset {}", self.tracked);
                                    break;
                                },
                            };
                        }
                    } else {
                        println_debug!("UPDATE: complete ooo chunk. Offset {}", self.cur_ooo_chunk_offset);

                        self.chunk_is_ooo = false;
                        self.cur_ooo_chunk_offset = 0;
                    }
                }
                if self.chunk_is_last == true {
                    println_debug!("last chunk, closing");
                    self.close();
                    self.chunk_is_last = false;
                } else {
                    println_debug!("NOT last chunk, keep going");

                }

            } else {
                if self.chunk_is_ooo == false {
                    let res = self.files.file_append(data);
                    if res != 0 { panic!("append failed"); }
                    self.tracked += data.len() as u64;
                } else {
                    // look up existing chunk (if any) and add our data to it
                    // TODO figure out how to do this w/o remove/insert
                    match self.chunks.remove(&self.cur_ooo_chunk_offset) {
                        Some(mut v) => {
                            v.extend(data);
                            println_debug!("UPDATE: appending data {} to ooo chunk at offset {}/{}", data.len(), self.cur_ooo_chunk_offset, self.tracked);
                            self.chunks.insert(self.cur_ooo_chunk_offset, v);
                        },
                        None => {
                            let mut v = Vec::with_capacity(32768); // TODO base on something
                            v.extend(data);
                            self.chunks.insert(self.cur_ooo_chunk_offset, v);
                        },
                    }
                }

                self.chunk_left -= data.len() as u32;
                consumed += data.len();
            }
        }
        self.files.files_prune();
        consumed as u32
    }
}


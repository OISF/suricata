#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct __BindgenBitfieldUnit<Storage> {
    storage: Storage,
}
impl<Storage> __BindgenBitfieldUnit<Storage> {
    #[inline]
    pub const fn new(storage: Storage) -> Self {
        Self { storage }
    }
}
impl<Storage> __BindgenBitfieldUnit<Storage>
where
    Storage: AsRef<[u8]> + AsMut<[u8]>,
{
    #[inline]
    fn extract_bit(byte: u8, index: usize) -> bool {
        let bit_index = if cfg!(target_endian = "big") {
            7 - (index % 8)
        } else {
            index % 8
        };
        let mask = 1 << bit_index;
        byte & mask == mask
    }
    #[inline]
    pub fn get_bit(&self, index: usize) -> bool {
        debug_assert!(index / 8 < self.storage.as_ref().len());
        let byte_index = index / 8;
        let byte = self.storage.as_ref()[byte_index];
        Self::extract_bit(byte, index)
    }
    #[inline]
    pub unsafe fn raw_get_bit(this: *const Self, index: usize) -> bool {
        debug_assert!(index / 8 < core::mem::size_of::<Storage>());
        let byte_index = index / 8;
        let byte = *(core::ptr::addr_of!((*this).storage) as *const u8).offset(byte_index as isize);
        Self::extract_bit(byte, index)
    }
    #[inline]
    fn change_bit(byte: u8, index: usize, val: bool) -> u8 {
        let bit_index = if cfg!(target_endian = "big") {
            7 - (index % 8)
        } else {
            index % 8
        };
        let mask = 1 << bit_index;
        if val {
            byte | mask
        } else {
            byte & !mask
        }
    }
    #[inline]
    pub fn set_bit(&mut self, index: usize, val: bool) {
        debug_assert!(index / 8 < self.storage.as_ref().len());
        let byte_index = index / 8;
        let byte = &mut self.storage.as_mut()[byte_index];
        *byte = Self::change_bit(*byte, index, val);
    }
    #[inline]
    pub unsafe fn raw_set_bit(this: *mut Self, index: usize, val: bool) {
        debug_assert!(index / 8 < core::mem::size_of::<Storage>());
        let byte_index = index / 8;
        let byte =
            (core::ptr::addr_of_mut!((*this).storage) as *mut u8).offset(byte_index as isize);
        *byte = Self::change_bit(*byte, index, val);
    }
    #[inline]
    pub fn get(&self, bit_offset: usize, bit_width: u8) -> u64 {
        debug_assert!(bit_width <= 64);
        debug_assert!(bit_offset / 8 < self.storage.as_ref().len());
        debug_assert!((bit_offset + (bit_width as usize)) / 8 <= self.storage.as_ref().len());
        let mut val = 0;
        for i in 0..(bit_width as usize) {
            if self.get_bit(i + bit_offset) {
                let index = if cfg!(target_endian = "big") {
                    bit_width as usize - 1 - i
                } else {
                    i
                };
                val |= 1 << index;
            }
        }
        val
    }
    #[inline]
    pub unsafe fn raw_get(this: *const Self, bit_offset: usize, bit_width: u8) -> u64 {
        debug_assert!(bit_width <= 64);
        debug_assert!(bit_offset / 8 < core::mem::size_of::<Storage>());
        debug_assert!((bit_offset + (bit_width as usize)) / 8 <= core::mem::size_of::<Storage>());
        let mut val = 0;
        for i in 0..(bit_width as usize) {
            if Self::raw_get_bit(this, i + bit_offset) {
                let index = if cfg!(target_endian = "big") {
                    bit_width as usize - 1 - i
                } else {
                    i
                };
                val |= 1 << index;
            }
        }
        val
    }
    #[inline]
    pub fn set(&mut self, bit_offset: usize, bit_width: u8, val: u64) {
        debug_assert!(bit_width <= 64);
        debug_assert!(bit_offset / 8 < self.storage.as_ref().len());
        debug_assert!((bit_offset + (bit_width as usize)) / 8 <= self.storage.as_ref().len());
        for i in 0..(bit_width as usize) {
            let mask = 1 << i;
            let val_bit_is_set = val & mask == mask;
            let index = if cfg!(target_endian = "big") {
                bit_width as usize - 1 - i
            } else {
                i
            };
            self.set_bit(index + bit_offset, val_bit_is_set);
        }
    }
    #[inline]
    pub unsafe fn raw_set(this: *mut Self, bit_offset: usize, bit_width: u8, val: u64) {
        debug_assert!(bit_width <= 64);
        debug_assert!(bit_offset / 8 < core::mem::size_of::<Storage>());
        debug_assert!((bit_offset + (bit_width as usize)) / 8 <= core::mem::size_of::<Storage>());
        for i in 0..(bit_width as usize) {
            let mask = 1 << i;
            let val_bit_is_set = val & mask == mask;
            let index = if cfg!(target_endian = "big") {
                bit_width as usize - 1 - i
            } else {
                i
            };
            Self::raw_set_bit(this, index + bit_offset, val_bit_is_set);
        }
    }
}
pub type __off_t = ::std::os::raw::c_long;
pub type __off64_t = ::std::os::raw::c_long;
pub type FILE = _IO_FILE;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _IO_marker {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _IO_codecvt {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _IO_wide_data {
    _unused: [u8; 0],
}
pub type _IO_lock_t = ::std::os::raw::c_void;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct _IO_FILE {
    pub _flags: ::std::os::raw::c_int,
    pub _IO_read_ptr: *mut ::std::os::raw::c_char,
    pub _IO_read_end: *mut ::std::os::raw::c_char,
    pub _IO_read_base: *mut ::std::os::raw::c_char,
    pub _IO_write_base: *mut ::std::os::raw::c_char,
    pub _IO_write_ptr: *mut ::std::os::raw::c_char,
    pub _IO_write_end: *mut ::std::os::raw::c_char,
    pub _IO_buf_base: *mut ::std::os::raw::c_char,
    pub _IO_buf_end: *mut ::std::os::raw::c_char,
    pub _IO_save_base: *mut ::std::os::raw::c_char,
    pub _IO_backup_base: *mut ::std::os::raw::c_char,
    pub _IO_save_end: *mut ::std::os::raw::c_char,
    pub _markers: *mut _IO_marker,
    pub _chain: *mut _IO_FILE,
    pub _fileno: ::std::os::raw::c_int,
    pub _flags2: ::std::os::raw::c_int,
    pub _old_offset: __off_t,
    pub _cur_column: ::std::os::raw::c_ushort,
    pub _vtable_offset: ::std::os::raw::c_schar,
    pub _shortbuf: [::std::os::raw::c_char; 1usize],
    pub _lock: *mut _IO_lock_t,
    pub _offset: __off64_t,
    pub _codecvt: *mut _IO_codecvt,
    pub _wide_data: *mut _IO_wide_data,
    pub _freeres_list: *mut _IO_FILE,
    pub _freeres_buf: *mut ::std::os::raw::c_void,
    pub _prevchain: *mut *mut _IO_FILE,
    pub _mode: ::std::os::raw::c_int,
    pub _unused2: [::std::os::raw::c_char; 20usize],
}
#[test]
fn bindgen_test_layout__IO_FILE() {
    const UNINIT: ::std::mem::MaybeUninit<_IO_FILE> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<_IO_FILE>(),
        216usize,
        "Size of _IO_FILE"
    );
    assert_eq!(
        ::std::mem::align_of::<_IO_FILE>(),
        8usize,
        "Alignment of _IO_FILE"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr)._flags) as usize - ptr as usize },
        0usize,
        "Offset of field: _IO_FILE::_flags"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr)._IO_read_ptr) as usize - ptr as usize },
        8usize,
        "Offset of field: _IO_FILE::_IO_read_ptr"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr)._IO_read_end) as usize - ptr as usize },
        16usize,
        "Offset of field: _IO_FILE::_IO_read_end"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr)._IO_read_base) as usize - ptr as usize },
        24usize,
        "Offset of field: _IO_FILE::_IO_read_base"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr)._IO_write_base) as usize - ptr as usize },
        32usize,
        "Offset of field: _IO_FILE::_IO_write_base"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr)._IO_write_ptr) as usize - ptr as usize },
        40usize,
        "Offset of field: _IO_FILE::_IO_write_ptr"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr)._IO_write_end) as usize - ptr as usize },
        48usize,
        "Offset of field: _IO_FILE::_IO_write_end"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr)._IO_buf_base) as usize - ptr as usize },
        56usize,
        "Offset of field: _IO_FILE::_IO_buf_base"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr)._IO_buf_end) as usize - ptr as usize },
        64usize,
        "Offset of field: _IO_FILE::_IO_buf_end"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr)._IO_save_base) as usize - ptr as usize },
        72usize,
        "Offset of field: _IO_FILE::_IO_save_base"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr)._IO_backup_base) as usize - ptr as usize },
        80usize,
        "Offset of field: _IO_FILE::_IO_backup_base"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr)._IO_save_end) as usize - ptr as usize },
        88usize,
        "Offset of field: _IO_FILE::_IO_save_end"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr)._markers) as usize - ptr as usize },
        96usize,
        "Offset of field: _IO_FILE::_markers"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr)._chain) as usize - ptr as usize },
        104usize,
        "Offset of field: _IO_FILE::_chain"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr)._fileno) as usize - ptr as usize },
        112usize,
        "Offset of field: _IO_FILE::_fileno"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr)._flags2) as usize - ptr as usize },
        116usize,
        "Offset of field: _IO_FILE::_flags2"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr)._old_offset) as usize - ptr as usize },
        120usize,
        "Offset of field: _IO_FILE::_old_offset"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr)._cur_column) as usize - ptr as usize },
        128usize,
        "Offset of field: _IO_FILE::_cur_column"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr)._vtable_offset) as usize - ptr as usize },
        130usize,
        "Offset of field: _IO_FILE::_vtable_offset"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr)._shortbuf) as usize - ptr as usize },
        131usize,
        "Offset of field: _IO_FILE::_shortbuf"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr)._lock) as usize - ptr as usize },
        136usize,
        "Offset of field: _IO_FILE::_lock"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr)._offset) as usize - ptr as usize },
        144usize,
        "Offset of field: _IO_FILE::_offset"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr)._codecvt) as usize - ptr as usize },
        152usize,
        "Offset of field: _IO_FILE::_codecvt"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr)._wide_data) as usize - ptr as usize },
        160usize,
        "Offset of field: _IO_FILE::_wide_data"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr)._freeres_list) as usize - ptr as usize },
        168usize,
        "Offset of field: _IO_FILE::_freeres_list"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr)._freeres_buf) as usize - ptr as usize },
        176usize,
        "Offset of field: _IO_FILE::_freeres_buf"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr)._prevchain) as usize - ptr as usize },
        184usize,
        "Offset of field: _IO_FILE::_prevchain"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr)._mode) as usize - ptr as usize },
        192usize,
        "Offset of field: _IO_FILE::_mode"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr)._unused2) as usize - ptr as usize },
        196usize,
        "Offset of field: _IO_FILE::_unused2"
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct __pthread_internal_list {
    pub __prev: *mut __pthread_internal_list,
    pub __next: *mut __pthread_internal_list,
}
#[test]
fn bindgen_test_layout___pthread_internal_list() {
    const UNINIT: ::std::mem::MaybeUninit<__pthread_internal_list> =
        ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<__pthread_internal_list>(),
        16usize,
        "Size of __pthread_internal_list"
    );
    assert_eq!(
        ::std::mem::align_of::<__pthread_internal_list>(),
        8usize,
        "Alignment of __pthread_internal_list"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).__prev) as usize - ptr as usize },
        0usize,
        "Offset of field: __pthread_internal_list::__prev"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).__next) as usize - ptr as usize },
        8usize,
        "Offset of field: __pthread_internal_list::__next"
    );
}
pub type __pthread_list_t = __pthread_internal_list;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct __pthread_mutex_s {
    pub __lock: ::std::os::raw::c_int,
    pub __count: ::std::os::raw::c_uint,
    pub __owner: ::std::os::raw::c_int,
    pub __nusers: ::std::os::raw::c_uint,
    pub __kind: ::std::os::raw::c_int,
    pub __spins: ::std::os::raw::c_short,
    pub __elision: ::std::os::raw::c_short,
    pub __list: __pthread_list_t,
}
#[test]
fn bindgen_test_layout___pthread_mutex_s() {
    const UNINIT: ::std::mem::MaybeUninit<__pthread_mutex_s> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<__pthread_mutex_s>(),
        40usize,
        "Size of __pthread_mutex_s"
    );
    assert_eq!(
        ::std::mem::align_of::<__pthread_mutex_s>(),
        8usize,
        "Alignment of __pthread_mutex_s"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).__lock) as usize - ptr as usize },
        0usize,
        "Offset of field: __pthread_mutex_s::__lock"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).__count) as usize - ptr as usize },
        4usize,
        "Offset of field: __pthread_mutex_s::__count"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).__owner) as usize - ptr as usize },
        8usize,
        "Offset of field: __pthread_mutex_s::__owner"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).__nusers) as usize - ptr as usize },
        12usize,
        "Offset of field: __pthread_mutex_s::__nusers"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).__kind) as usize - ptr as usize },
        16usize,
        "Offset of field: __pthread_mutex_s::__kind"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).__spins) as usize - ptr as usize },
        20usize,
        "Offset of field: __pthread_mutex_s::__spins"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).__elision) as usize - ptr as usize },
        22usize,
        "Offset of field: __pthread_mutex_s::__elision"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).__list) as usize - ptr as usize },
        24usize,
        "Offset of field: __pthread_mutex_s::__list"
    );
}
pub type pthread_t = ::std::os::raw::c_ulong;
#[repr(C)]
#[derive(Copy, Clone)]
pub union pthread_mutex_t {
    pub __data: __pthread_mutex_s,
    pub __size: [::std::os::raw::c_char; 40usize],
    pub __align: ::std::os::raw::c_long,
}
#[test]
fn bindgen_test_layout_pthread_mutex_t() {
    const UNINIT: ::std::mem::MaybeUninit<pthread_mutex_t> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<pthread_mutex_t>(),
        40usize,
        "Size of pthread_mutex_t"
    );
    assert_eq!(
        ::std::mem::align_of::<pthread_mutex_t>(),
        8usize,
        "Alignment of pthread_mutex_t"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).__data) as usize - ptr as usize },
        0usize,
        "Offset of field: pthread_mutex_t::__data"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).__size) as usize - ptr as usize },
        0usize,
        "Offset of field: pthread_mutex_t::__size"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).__align) as usize - ptr as usize },
        0usize,
        "Offset of field: pthread_mutex_t::__align"
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct pcre2_real_code_8 {
    _unused: [u8; 0],
}
pub type pcre2_code_8 = pcre2_real_code_8;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct pcre2_real_match_data_8 {
    _unused: [u8; 0],
}
pub type pcre2_match_data_8 = pcre2_real_match_data_8;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SCTime_t {
    pub _bitfield_align_1: [u64; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 8usize]>,
}
#[test]
fn bindgen_test_layout_SCTime_t() {
    assert_eq!(
        ::std::mem::size_of::<SCTime_t>(),
        8usize,
        "Size of SCTime_t"
    );
    assert_eq!(
        ::std::mem::align_of::<SCTime_t>(),
        8usize,
        "Alignment of SCTime_t"
    );
}
impl SCTime_t {
    #[inline]
    pub fn secs(&self) -> u64 {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(0usize, 44u8) as u64) }
    }
    #[inline]
    pub fn set_secs(&mut self, val: u64) {
        unsafe {
            let val: u64 = ::std::mem::transmute(val);
            self._bitfield_1.set(0usize, 44u8, val as u64)
        }
    }
    #[inline]
    pub unsafe fn secs_raw(this: *const Self) -> u64 {
        unsafe {
            ::std::mem::transmute(<__BindgenBitfieldUnit<[u8; 8usize]>>::raw_get(
                ::std::ptr::addr_of!((*this)._bitfield_1),
                0usize,
                44u8,
            ) as u64)
        }
    }
    #[inline]
    pub unsafe fn set_secs_raw(this: *mut Self, val: u64) {
        unsafe {
            let val: u64 = ::std::mem::transmute(val);
            <__BindgenBitfieldUnit<[u8; 8usize]>>::raw_set(
                ::std::ptr::addr_of_mut!((*this)._bitfield_1),
                0usize,
                44u8,
                val as u64,
            )
        }
    }
    #[inline]
    pub fn usecs(&self) -> u64 {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(44usize, 20u8) as u64) }
    }
    #[inline]
    pub fn set_usecs(&mut self, val: u64) {
        unsafe {
            let val: u64 = ::std::mem::transmute(val);
            self._bitfield_1.set(44usize, 20u8, val as u64)
        }
    }
    #[inline]
    pub unsafe fn usecs_raw(this: *const Self) -> u64 {
        unsafe {
            ::std::mem::transmute(<__BindgenBitfieldUnit<[u8; 8usize]>>::raw_get(
                ::std::ptr::addr_of!((*this)._bitfield_1),
                44usize,
                20u8,
            ) as u64)
        }
    }
    #[inline]
    pub unsafe fn set_usecs_raw(this: *mut Self, val: u64) {
        unsafe {
            let val: u64 = ::std::mem::transmute(val);
            <__BindgenBitfieldUnit<[u8; 8usize]>>::raw_set(
                ::std::ptr::addr_of_mut!((*this)._bitfield_1),
                44usize,
                20u8,
                val as u64,
            )
        }
    }
    #[inline]
    pub fn new_bitfield_1(secs: u64, usecs: u64) -> __BindgenBitfieldUnit<[u8; 8usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 8usize]> = Default::default();
        __bindgen_bitfield_unit.set(0usize, 44u8, {
            let secs: u64 = unsafe { ::std::mem::transmute(secs) };
            secs as u64
        });
        __bindgen_bitfield_unit.set(44usize, 20u8, {
            let usecs: u64 = unsafe { ::std::mem::transmute(usecs) };
            usecs as u64
        });
        __bindgen_bitfield_unit
    }
}
#[doc = " Structure to define a Suricata plugin."]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SCPlugin_ {
    pub name: *const ::std::os::raw::c_char,
    pub license: *const ::std::os::raw::c_char,
    pub author: *const ::std::os::raw::c_char,
    pub Init: ::std::option::Option<unsafe extern "C" fn()>,
}
#[test]
fn bindgen_test_layout_SCPlugin_() {
    const UNINIT: ::std::mem::MaybeUninit<SCPlugin_> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<SCPlugin_>(),
        32usize,
        "Size of SCPlugin_"
    );
    assert_eq!(
        ::std::mem::align_of::<SCPlugin_>(),
        8usize,
        "Alignment of SCPlugin_"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).name) as usize - ptr as usize },
        0usize,
        "Offset of field: SCPlugin_::name"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).license) as usize - ptr as usize },
        8usize,
        "Offset of field: SCPlugin_::license"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).author) as usize - ptr as usize },
        16usize,
        "Offset of field: SCPlugin_::author"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).Init) as usize - ptr as usize },
        24usize,
        "Offset of field: SCPlugin_::Init"
    );
}
#[doc = " Structure to define a Suricata plugin."]
pub type SCPlugin = SCPlugin_;
pub type SCPluginRegisterFunc = ::std::option::Option<unsafe extern "C" fn() -> *mut SCPlugin>;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SCCapturePlugin_ {
    pub name: *mut ::std::os::raw::c_char,
    pub Init: ::std::option::Option<
        unsafe extern "C" fn(
            args: *const ::std::os::raw::c_char,
            plugin_slot: ::std::os::raw::c_int,
            receive_slot: ::std::os::raw::c_int,
            decode_slot: ::std::os::raw::c_int,
        ),
    >,
    pub ThreadInit: ::std::option::Option<
        unsafe extern "C" fn(
            ctx: *mut ::std::os::raw::c_void,
            thread_id: ::std::os::raw::c_int,
            thread_ctx: *mut *mut ::std::os::raw::c_void,
        ) -> ::std::os::raw::c_int,
    >,
    pub ThreadDeinit: ::std::option::Option<
        unsafe extern "C" fn(
            ctx: *mut ::std::os::raw::c_void,
            thread_ctx: *mut ::std::os::raw::c_void,
        ) -> ::std::os::raw::c_int,
    >,
    pub GetDefaultMode:
        ::std::option::Option<unsafe extern "C" fn() -> *const ::std::os::raw::c_char>,
    pub entries: SCCapturePlugin___bindgen_ty_1,
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SCCapturePlugin___bindgen_ty_1 {
    pub tqe_next: *mut SCCapturePlugin_,
    pub tqe_prev: *mut *mut SCCapturePlugin_,
}
#[test]
fn bindgen_test_layout_SCCapturePlugin___bindgen_ty_1() {
    const UNINIT: ::std::mem::MaybeUninit<SCCapturePlugin___bindgen_ty_1> =
        ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<SCCapturePlugin___bindgen_ty_1>(),
        16usize,
        "Size of SCCapturePlugin___bindgen_ty_1"
    );
    assert_eq!(
        ::std::mem::align_of::<SCCapturePlugin___bindgen_ty_1>(),
        8usize,
        "Alignment of SCCapturePlugin___bindgen_ty_1"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).tqe_next) as usize - ptr as usize },
        0usize,
        "Offset of field: SCCapturePlugin___bindgen_ty_1::tqe_next"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).tqe_prev) as usize - ptr as usize },
        8usize,
        "Offset of field: SCCapturePlugin___bindgen_ty_1::tqe_prev"
    );
}
#[test]
fn bindgen_test_layout_SCCapturePlugin_() {
    const UNINIT: ::std::mem::MaybeUninit<SCCapturePlugin_> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<SCCapturePlugin_>(),
        56usize,
        "Size of SCCapturePlugin_"
    );
    assert_eq!(
        ::std::mem::align_of::<SCCapturePlugin_>(),
        8usize,
        "Alignment of SCCapturePlugin_"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).name) as usize - ptr as usize },
        0usize,
        "Offset of field: SCCapturePlugin_::name"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).Init) as usize - ptr as usize },
        8usize,
        "Offset of field: SCCapturePlugin_::Init"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).ThreadInit) as usize - ptr as usize },
        16usize,
        "Offset of field: SCCapturePlugin_::ThreadInit"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).ThreadDeinit) as usize - ptr as usize },
        24usize,
        "Offset of field: SCCapturePlugin_::ThreadDeinit"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).GetDefaultMode) as usize - ptr as usize },
        32usize,
        "Offset of field: SCCapturePlugin_::GetDefaultMode"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).entries) as usize - ptr as usize },
        40usize,
        "Offset of field: SCCapturePlugin_::entries"
    );
}
pub type SCCapturePlugin = SCCapturePlugin_;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SCAppLayerPlugin_ {
    pub version: u64,
    pub name: *mut ::std::os::raw::c_char,
    pub Register: ::std::option::Option<unsafe extern "C" fn()>,
    pub KeywordsRegister: ::std::option::Option<unsafe extern "C" fn()>,
    pub logname: *mut ::std::os::raw::c_char,
    pub confname: *mut ::std::os::raw::c_char,
    pub Logger: ::std::option::Option<
        unsafe extern "C" fn(
            tx: *mut ::std::os::raw::c_void,
            jb: *mut ::std::os::raw::c_void,
        ) -> bool,
    >,
}
#[test]
fn bindgen_test_layout_SCAppLayerPlugin_() {
    const UNINIT: ::std::mem::MaybeUninit<SCAppLayerPlugin_> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<SCAppLayerPlugin_>(),
        56usize,
        "Size of SCAppLayerPlugin_"
    );
    assert_eq!(
        ::std::mem::align_of::<SCAppLayerPlugin_>(),
        8usize,
        "Alignment of SCAppLayerPlugin_"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).version) as usize - ptr as usize },
        0usize,
        "Offset of field: SCAppLayerPlugin_::version"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).name) as usize - ptr as usize },
        8usize,
        "Offset of field: SCAppLayerPlugin_::name"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).Register) as usize - ptr as usize },
        16usize,
        "Offset of field: SCAppLayerPlugin_::Register"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).KeywordsRegister) as usize - ptr as usize },
        24usize,
        "Offset of field: SCAppLayerPlugin_::KeywordsRegister"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).logname) as usize - ptr as usize },
        32usize,
        "Offset of field: SCAppLayerPlugin_::logname"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).confname) as usize - ptr as usize },
        40usize,
        "Offset of field: SCAppLayerPlugin_::confname"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).Logger) as usize - ptr as usize },
        48usize,
        "Offset of field: SCAppLayerPlugin_::Logger"
    );
}
pub type SCAppLayerPlugin = SCAppLayerPlugin_;
#[repr(u32)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum SCError {
    SC_OK = 0,
    SC_ENOMEM = 1,
    SC_EINVAL = 2,
    SC_ELIMIT = 3,
    SC_EEXIST = 4,
    SC_ENOENT = 5,
    SC_ERR_MAX = 6,
}
#[doc = " \\brief Structure used to hold the line_no details of a FG filter"]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SCLogFGFilterLine_ {
    pub line: ::std::os::raw::c_int,
    pub next: *mut SCLogFGFilterLine_,
}
#[test]
fn bindgen_test_layout_SCLogFGFilterLine_() {
    const UNINIT: ::std::mem::MaybeUninit<SCLogFGFilterLine_> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<SCLogFGFilterLine_>(),
        16usize,
        "Size of SCLogFGFilterLine_"
    );
    assert_eq!(
        ::std::mem::align_of::<SCLogFGFilterLine_>(),
        8usize,
        "Alignment of SCLogFGFilterLine_"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).line) as usize - ptr as usize },
        0usize,
        "Offset of field: SCLogFGFilterLine_::line"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).next) as usize - ptr as usize },
        8usize,
        "Offset of field: SCLogFGFilterLine_::next"
    );
}
#[doc = " \\brief Structure used to hold the line_no details of a FG filter"]
pub type SCLogFGFilterLine = SCLogFGFilterLine_;
#[doc = " \\brief structure used to hold the function details of a FG filter"]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SCLogFGFilterFunc_ {
    pub func: *mut ::std::os::raw::c_char,
    pub line: *mut SCLogFGFilterLine,
    pub next: *mut SCLogFGFilterFunc_,
}
#[test]
fn bindgen_test_layout_SCLogFGFilterFunc_() {
    const UNINIT: ::std::mem::MaybeUninit<SCLogFGFilterFunc_> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<SCLogFGFilterFunc_>(),
        24usize,
        "Size of SCLogFGFilterFunc_"
    );
    assert_eq!(
        ::std::mem::align_of::<SCLogFGFilterFunc_>(),
        8usize,
        "Alignment of SCLogFGFilterFunc_"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).func) as usize - ptr as usize },
        0usize,
        "Offset of field: SCLogFGFilterFunc_::func"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).line) as usize - ptr as usize },
        8usize,
        "Offset of field: SCLogFGFilterFunc_::line"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).next) as usize - ptr as usize },
        16usize,
        "Offset of field: SCLogFGFilterFunc_::next"
    );
}
#[doc = " \\brief structure used to hold the function details of a FG filter"]
pub type SCLogFGFilterFunc = SCLogFGFilterFunc_;
#[doc = " \\brief Structure used to hold FG filters.  Encapsulates filename details,\n        func details, which inturn encapsulates the line_no details"]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SCLogFGFilterFile_ {
    pub file: *mut ::std::os::raw::c_char,
    pub func: *mut SCLogFGFilterFunc,
    pub next: *mut SCLogFGFilterFile_,
}
#[test]
fn bindgen_test_layout_SCLogFGFilterFile_() {
    const UNINIT: ::std::mem::MaybeUninit<SCLogFGFilterFile_> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<SCLogFGFilterFile_>(),
        24usize,
        "Size of SCLogFGFilterFile_"
    );
    assert_eq!(
        ::std::mem::align_of::<SCLogFGFilterFile_>(),
        8usize,
        "Alignment of SCLogFGFilterFile_"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).file) as usize - ptr as usize },
        0usize,
        "Offset of field: SCLogFGFilterFile_::file"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).func) as usize - ptr as usize },
        8usize,
        "Offset of field: SCLogFGFilterFile_::func"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).next) as usize - ptr as usize },
        16usize,
        "Offset of field: SCLogFGFilterFile_::next"
    );
}
#[doc = " \\brief Structure used to hold FG filters.  Encapsulates filename details,\n        func details, which inturn encapsulates the line_no details"]
pub type SCLogFGFilterFile = SCLogFGFilterFile_;
#[doc = " \\brief Structure used to hold the thread_list used by FD filters"]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SCLogFDFilterThreadList_ {
    pub entered: ::std::os::raw::c_int,
    pub t: pthread_t,
    pub next: *mut SCLogFDFilterThreadList_,
}
#[test]
fn bindgen_test_layout_SCLogFDFilterThreadList_() {
    const UNINIT: ::std::mem::MaybeUninit<SCLogFDFilterThreadList_> =
        ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<SCLogFDFilterThreadList_>(),
        24usize,
        "Size of SCLogFDFilterThreadList_"
    );
    assert_eq!(
        ::std::mem::align_of::<SCLogFDFilterThreadList_>(),
        8usize,
        "Alignment of SCLogFDFilterThreadList_"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).entered) as usize - ptr as usize },
        0usize,
        "Offset of field: SCLogFDFilterThreadList_::entered"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).t) as usize - ptr as usize },
        8usize,
        "Offset of field: SCLogFDFilterThreadList_::t"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).next) as usize - ptr as usize },
        16usize,
        "Offset of field: SCLogFDFilterThreadList_::next"
    );
}
#[doc = " \\brief Structure used to hold the thread_list used by FD filters"]
pub type SCLogFDFilterThreadList = SCLogFDFilterThreadList_;
#[doc = " \\brief Structure that holds the FD filters"]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SCLogFDFilter_ {
    pub func: *mut ::std::os::raw::c_char,
    pub next: *mut SCLogFDFilter_,
}
#[test]
fn bindgen_test_layout_SCLogFDFilter_() {
    const UNINIT: ::std::mem::MaybeUninit<SCLogFDFilter_> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<SCLogFDFilter_>(),
        16usize,
        "Size of SCLogFDFilter_"
    );
    assert_eq!(
        ::std::mem::align_of::<SCLogFDFilter_>(),
        8usize,
        "Alignment of SCLogFDFilter_"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).func) as usize - ptr as usize },
        0usize,
        "Offset of field: SCLogFDFilter_::func"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).next) as usize - ptr as usize },
        8usize,
        "Offset of field: SCLogFDFilter_::next"
    );
}
#[doc = " \\brief Structure that holds the FD filters"]
pub type SCLogFDFilter = SCLogFDFilter_;
#[repr(i32)]
#[doc = " \\brief The various log levels\n NOTE: when adding new level, don't forget to update SCLogMapLogLevelToSyslogLevel()\n      or it may result in logging to syslog with LOG_EMERG priority."]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum SCLogLevel {
    SC_LOG_NOTSET = -1,
    SC_LOG_NONE = 0,
    SC_LOG_ERROR = 1,
    SC_LOG_WARNING = 2,
    SC_LOG_NOTICE = 3,
    SC_LOG_INFO = 4,
    SC_LOG_PERF = 5,
    SC_LOG_CONFIG = 6,
    SC_LOG_DEBUG = 7,
    SC_LOG_LEVEL_MAX = 8,
}
#[repr(u32)]
#[doc = " \\brief The various output interfaces supported"]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum SCLogOPIface {
    SC_LOG_OP_IFACE_CONSOLE = 0,
    SC_LOG_OP_IFACE_FILE = 1,
    SC_LOG_OP_IFACE_SYSLOG = 2,
    SC_LOG_OP_IFACE_MAX = 3,
}
#[repr(u32)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum SCLogOPType {
    SC_LOG_OP_TYPE_REGULAR = 0,
    SC_LOG_OP_TYPE_JSON = 1,
}
#[doc = " \\brief Structure to be used when log_level override support would be provided\n        by the logging module"]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SCLogOPBuffer_ {
    pub msg: [::std::os::raw::c_char; 2048usize],
    pub temp: *mut ::std::os::raw::c_char,
    pub log_format: *const ::std::os::raw::c_char,
}
#[test]
fn bindgen_test_layout_SCLogOPBuffer_() {
    const UNINIT: ::std::mem::MaybeUninit<SCLogOPBuffer_> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<SCLogOPBuffer_>(),
        2064usize,
        "Size of SCLogOPBuffer_"
    );
    assert_eq!(
        ::std::mem::align_of::<SCLogOPBuffer_>(),
        8usize,
        "Alignment of SCLogOPBuffer_"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).msg) as usize - ptr as usize },
        0usize,
        "Offset of field: SCLogOPBuffer_::msg"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).temp) as usize - ptr as usize },
        2048usize,
        "Offset of field: SCLogOPBuffer_::temp"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).log_format) as usize - ptr as usize },
        2056usize,
        "Offset of field: SCLogOPBuffer_::log_format"
    );
}
#[doc = " \\brief Structure to be used when log_level override support would be provided\n        by the logging module"]
pub type SCLogOPBuffer = SCLogOPBuffer_;
#[doc = " \\brief The output interface context for the logging module"]
#[repr(C)]
#[derive(Copy, Clone)]
pub struct SCLogOPIfaceCtx_ {
    pub iface: SCLogOPIface,
    pub use_color: bool,
    pub type_: SCLogOPType,
    pub file: *const ::std::os::raw::c_char,
    pub file_d: *mut FILE,
    pub rotation_flag: ::std::os::raw::c_int,
    pub facility: ::std::os::raw::c_int,
    pub log_level: SCLogLevel,
    pub log_format: *const ::std::os::raw::c_char,
    pub fp_mutex: pthread_mutex_t,
    pub next: *mut SCLogOPIfaceCtx_,
}
#[test]
fn bindgen_test_layout_SCLogOPIfaceCtx_() {
    const UNINIT: ::std::mem::MaybeUninit<SCLogOPIfaceCtx_> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<SCLogOPIfaceCtx_>(),
        104usize,
        "Size of SCLogOPIfaceCtx_"
    );
    assert_eq!(
        ::std::mem::align_of::<SCLogOPIfaceCtx_>(),
        8usize,
        "Alignment of SCLogOPIfaceCtx_"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).iface) as usize - ptr as usize },
        0usize,
        "Offset of field: SCLogOPIfaceCtx_::iface"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).use_color) as usize - ptr as usize },
        4usize,
        "Offset of field: SCLogOPIfaceCtx_::use_color"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).type_) as usize - ptr as usize },
        8usize,
        "Offset of field: SCLogOPIfaceCtx_::type_"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).file) as usize - ptr as usize },
        16usize,
        "Offset of field: SCLogOPIfaceCtx_::file"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).file_d) as usize - ptr as usize },
        24usize,
        "Offset of field: SCLogOPIfaceCtx_::file_d"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).rotation_flag) as usize - ptr as usize },
        32usize,
        "Offset of field: SCLogOPIfaceCtx_::rotation_flag"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).facility) as usize - ptr as usize },
        36usize,
        "Offset of field: SCLogOPIfaceCtx_::facility"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).log_level) as usize - ptr as usize },
        40usize,
        "Offset of field: SCLogOPIfaceCtx_::log_level"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).log_format) as usize - ptr as usize },
        48usize,
        "Offset of field: SCLogOPIfaceCtx_::log_format"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).fp_mutex) as usize - ptr as usize },
        56usize,
        "Offset of field: SCLogOPIfaceCtx_::fp_mutex"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).next) as usize - ptr as usize },
        96usize,
        "Offset of field: SCLogOPIfaceCtx_::next"
    );
}
#[doc = " \\brief The output interface context for the logging module"]
pub type SCLogOPIfaceCtx = SCLogOPIfaceCtx_;
#[doc = " \\brief Structure containing init data, that would be passed to\n        SCInitDebugModule()"]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SCLogInitData_ {
    pub startup_message: *const ::std::os::raw::c_char,
    pub global_log_level: SCLogLevel,
    pub global_log_format: *const ::std::os::raw::c_char,
    pub op_filter: *const ::std::os::raw::c_char,
    pub op_ifaces: *mut SCLogOPIfaceCtx,
    pub op_ifaces_cnt: u8,
}
#[test]
fn bindgen_test_layout_SCLogInitData_() {
    const UNINIT: ::std::mem::MaybeUninit<SCLogInitData_> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<SCLogInitData_>(),
        48usize,
        "Size of SCLogInitData_"
    );
    assert_eq!(
        ::std::mem::align_of::<SCLogInitData_>(),
        8usize,
        "Alignment of SCLogInitData_"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).startup_message) as usize - ptr as usize },
        0usize,
        "Offset of field: SCLogInitData_::startup_message"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).global_log_level) as usize - ptr as usize },
        8usize,
        "Offset of field: SCLogInitData_::global_log_level"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).global_log_format) as usize - ptr as usize },
        16usize,
        "Offset of field: SCLogInitData_::global_log_format"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).op_filter) as usize - ptr as usize },
        24usize,
        "Offset of field: SCLogInitData_::op_filter"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).op_ifaces) as usize - ptr as usize },
        32usize,
        "Offset of field: SCLogInitData_::op_ifaces"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).op_ifaces_cnt) as usize - ptr as usize },
        40usize,
        "Offset of field: SCLogInitData_::op_ifaces_cnt"
    );
}
#[doc = " \\brief Structure containing init data, that would be passed to\n        SCInitDebugModule()"]
pub type SCLogInitData = SCLogInitData_;
#[doc = " \\brief Holds the config state used by the logging api"]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SCLogConfig_ {
    pub startup_message: *mut ::std::os::raw::c_char,
    pub log_level: SCLogLevel,
    pub log_format: *mut ::std::os::raw::c_char,
    pub op_filter: *mut ::std::os::raw::c_char,
    pub op_filter_regex: *mut pcre2_code_8,
    pub op_filter_regex_match: *mut pcre2_match_data_8,
    pub op_ifaces: *mut SCLogOPIfaceCtx,
    pub op_ifaces_cnt: u8,
}
#[test]
fn bindgen_test_layout_SCLogConfig_() {
    const UNINIT: ::std::mem::MaybeUninit<SCLogConfig_> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<SCLogConfig_>(),
        64usize,
        "Size of SCLogConfig_"
    );
    assert_eq!(
        ::std::mem::align_of::<SCLogConfig_>(),
        8usize,
        "Alignment of SCLogConfig_"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).startup_message) as usize - ptr as usize },
        0usize,
        "Offset of field: SCLogConfig_::startup_message"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).log_level) as usize - ptr as usize },
        8usize,
        "Offset of field: SCLogConfig_::log_level"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).log_format) as usize - ptr as usize },
        16usize,
        "Offset of field: SCLogConfig_::log_format"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).op_filter) as usize - ptr as usize },
        24usize,
        "Offset of field: SCLogConfig_::op_filter"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).op_filter_regex) as usize - ptr as usize },
        32usize,
        "Offset of field: SCLogConfig_::op_filter_regex"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).op_filter_regex_match) as usize - ptr as usize },
        40usize,
        "Offset of field: SCLogConfig_::op_filter_regex_match"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).op_ifaces) as usize - ptr as usize },
        48usize,
        "Offset of field: SCLogConfig_::op_ifaces"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).op_ifaces_cnt) as usize - ptr as usize },
        56usize,
        "Offset of field: SCLogConfig_::op_ifaces_cnt"
    );
}
#[doc = " \\brief Holds the config state used by the logging api"]
pub type SCLogConfig = SCLogConfig_;
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct SCTPHdr_ {
    pub sh_sport: u16,
    pub sh_dport: u16,
    pub sh_vtag: u32,
    pub sh_sum: u32,
}
#[test]
fn bindgen_test_layout_SCTPHdr_() {
    const UNINIT: ::std::mem::MaybeUninit<SCTPHdr_> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<SCTPHdr_>(),
        12usize,
        "Size of SCTPHdr_"
    );
    assert_eq!(
        ::std::mem::align_of::<SCTPHdr_>(),
        1usize,
        "Alignment of SCTPHdr_"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).sh_sport) as usize - ptr as usize },
        0usize,
        "Offset of field: SCTPHdr_::sh_sport"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).sh_dport) as usize - ptr as usize },
        2usize,
        "Offset of field: SCTPHdr_::sh_dport"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).sh_vtag) as usize - ptr as usize },
        4usize,
        "Offset of field: SCTPHdr_::sh_vtag"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).sh_sum) as usize - ptr as usize },
        8usize,
        "Offset of field: SCTPHdr_::sh_sum"
    );
}
pub type SCTPHdr = SCTPHdr_;
#[repr(u32)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum SCAppLayerEventType {
    APP_LAYER_EVENT_TYPE_TRANSACTION = 1,
    APP_LAYER_EVENT_TYPE_PACKET = 2,
}
pub type SCAppLayerStateGetEventInfoByIdFn = ::std::option::Option<
    unsafe extern "C" fn(
        event_id: u8,
        event_name: *mut *const ::std::os::raw::c_char,
        event_type: *mut SCAppLayerEventType,
    ) -> ::std::os::raw::c_int,
>;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SCEnumCharMap_ {
    pub enum_name: *const ::std::os::raw::c_char,
    pub enum_value: ::std::os::raw::c_int,
}
#[test]
fn bindgen_test_layout_SCEnumCharMap_() {
    const UNINIT: ::std::mem::MaybeUninit<SCEnumCharMap_> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<SCEnumCharMap_>(),
        16usize,
        "Size of SCEnumCharMap_"
    );
    assert_eq!(
        ::std::mem::align_of::<SCEnumCharMap_>(),
        8usize,
        "Alignment of SCEnumCharMap_"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).enum_name) as usize - ptr as usize },
        0usize,
        "Offset of field: SCEnumCharMap_::enum_name"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).enum_value) as usize - ptr as usize },
        8usize,
        "Offset of field: SCEnumCharMap_::enum_value"
    );
}
pub type SCEnumCharMap = SCEnumCharMap_;
#[repr(u32)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum AppProtoEnum {
    ALPROTO_UNKNOWN = 0,
    ALPROTO_FAILED = 1,
    ALPROTO_HTTP1 = 2,
    ALPROTO_FTP = 3,
    ALPROTO_SMTP = 4,
    ALPROTO_TLS = 5,
    ALPROTO_SSH = 6,
    ALPROTO_IMAP = 7,
    ALPROTO_JABBER = 8,
    ALPROTO_SMB = 9,
    ALPROTO_DCERPC = 10,
    ALPROTO_IRC = 11,
    ALPROTO_DNS = 12,
    ALPROTO_MODBUS = 13,
    ALPROTO_ENIP = 14,
    ALPROTO_DNP3 = 15,
    ALPROTO_NFS = 16,
    ALPROTO_NTP = 17,
    ALPROTO_FTPDATA = 18,
    ALPROTO_TFTP = 19,
    ALPROTO_IKE = 20,
    ALPROTO_KRB5 = 21,
    ALPROTO_QUIC = 22,
    ALPROTO_DHCP = 23,
    ALPROTO_SNMP = 24,
    ALPROTO_SIP = 25,
    ALPROTO_RFB = 26,
    ALPROTO_MQTT = 27,
    ALPROTO_PGSQL = 28,
    ALPROTO_TELNET = 29,
    ALPROTO_WEBSOCKET = 30,
    ALPROTO_LDAP = 31,
    ALPROTO_DOH2 = 32,
    ALPROTO_TEMPLATE = 33,
    ALPROTO_RDP = 34,
    ALPROTO_HTTP2 = 35,
    ALPROTO_BITTORRENT_DHT = 36,
    ALPROTO_POP3 = 37,
    ALPROTO_HTTP = 38,
    ALPROTO_MAX_STATIC = 39,
}
pub type AppProto = u16;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct RadixUserData {
    _unused: [u8; 0],
}
#[doc = " \\brief Structure for the node in the radix tree"]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SCRadix4Node_ {
    pub _bitfield_align_1: [u64; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 8usize]>,
    #[doc = " the bit position where the bits differ in the nodes children.  Used\n  to determine the path to be taken during a lookup"]
    pub bit: u8,
    #[doc = " bool to see if prefix_stream is filled"]
    pub has_prefix: bool,
    #[doc = " the key that has been stored in the tree"]
    pub prefix_stream: [u8; 4usize],
    #[doc = " User data that is associated with this key. We need a user data field\n for each netblock value possible since one ip can be associated\n with any of the 32 netblocks."]
    pub user_data: *mut RadixUserData,
    #[doc = " the left and the right children of a node"]
    pub left: *mut SCRadix4Node_,
    #[doc = " the left and the right children of a node"]
    pub right: *mut SCRadix4Node_,
    #[doc = " the parent node for this tree"]
    pub parent: *mut SCRadix4Node_,
}
#[test]
fn bindgen_test_layout_SCRadix4Node_() {
    const UNINIT: ::std::mem::MaybeUninit<SCRadix4Node_> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<SCRadix4Node_>(),
        48usize,
        "Size of SCRadix4Node_"
    );
    assert_eq!(
        ::std::mem::align_of::<SCRadix4Node_>(),
        8usize,
        "Alignment of SCRadix4Node_"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).bit) as usize - ptr as usize },
        8usize,
        "Offset of field: SCRadix4Node_::bit"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).has_prefix) as usize - ptr as usize },
        9usize,
        "Offset of field: SCRadix4Node_::has_prefix"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).prefix_stream) as usize - ptr as usize },
        10usize,
        "Offset of field: SCRadix4Node_::prefix_stream"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).user_data) as usize - ptr as usize },
        16usize,
        "Offset of field: SCRadix4Node_::user_data"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).left) as usize - ptr as usize },
        24usize,
        "Offset of field: SCRadix4Node_::left"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).right) as usize - ptr as usize },
        32usize,
        "Offset of field: SCRadix4Node_::right"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).parent) as usize - ptr as usize },
        40usize,
        "Offset of field: SCRadix4Node_::parent"
    );
}
impl SCRadix4Node_ {
    #[inline]
    pub fn masks(&self) -> u64 {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(0usize, 33u8) as u64) }
    }
    #[inline]
    pub fn set_masks(&mut self, val: u64) {
        unsafe {
            let val: u64 = ::std::mem::transmute(val);
            self._bitfield_1.set(0usize, 33u8, val as u64)
        }
    }
    #[inline]
    pub unsafe fn masks_raw(this: *const Self) -> u64 {
        unsafe {
            ::std::mem::transmute(<__BindgenBitfieldUnit<[u8; 8usize]>>::raw_get(
                ::std::ptr::addr_of!((*this)._bitfield_1),
                0usize,
                33u8,
            ) as u64)
        }
    }
    #[inline]
    pub unsafe fn set_masks_raw(this: *mut Self, val: u64) {
        unsafe {
            let val: u64 = ::std::mem::transmute(val);
            <__BindgenBitfieldUnit<[u8; 8usize]>>::raw_set(
                ::std::ptr::addr_of_mut!((*this)._bitfield_1),
                0usize,
                33u8,
                val as u64,
            )
        }
    }
    #[inline]
    pub fn pad1(&self) -> u64 {
        unsafe { ::std::mem::transmute(self._bitfield_1.get(33usize, 31u8) as u64) }
    }
    #[inline]
    pub fn set_pad1(&mut self, val: u64) {
        unsafe {
            let val: u64 = ::std::mem::transmute(val);
            self._bitfield_1.set(33usize, 31u8, val as u64)
        }
    }
    #[inline]
    pub unsafe fn pad1_raw(this: *const Self) -> u64 {
        unsafe {
            ::std::mem::transmute(<__BindgenBitfieldUnit<[u8; 8usize]>>::raw_get(
                ::std::ptr::addr_of!((*this)._bitfield_1),
                33usize,
                31u8,
            ) as u64)
        }
    }
    #[inline]
    pub unsafe fn set_pad1_raw(this: *mut Self, val: u64) {
        unsafe {
            let val: u64 = ::std::mem::transmute(val);
            <__BindgenBitfieldUnit<[u8; 8usize]>>::raw_set(
                ::std::ptr::addr_of_mut!((*this)._bitfield_1),
                33usize,
                31u8,
                val as u64,
            )
        }
    }
    #[inline]
    pub fn new_bitfield_1(masks: u64, pad1: u64) -> __BindgenBitfieldUnit<[u8; 8usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 8usize]> = Default::default();
        __bindgen_bitfield_unit.set(0usize, 33u8, {
            let masks: u64 = unsafe { ::std::mem::transmute(masks) };
            masks as u64
        });
        __bindgen_bitfield_unit.set(33usize, 31u8, {
            let pad1: u64 = unsafe { ::std::mem::transmute(pad1) };
            pad1 as u64
        });
        __bindgen_bitfield_unit
    }
}
#[doc = " \\brief Structure for the node in the radix tree"]
pub type SCRadix4Node = SCRadix4Node_;
#[doc = " \\brief Structure for the radix tree"]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SCRadix4Tree_ {
    #[doc = " the root node in the radix tree"]
    pub head: *mut SCRadix4Node,
}
#[test]
fn bindgen_test_layout_SCRadix4Tree_() {
    const UNINIT: ::std::mem::MaybeUninit<SCRadix4Tree_> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<SCRadix4Tree_>(),
        8usize,
        "Size of SCRadix4Tree_"
    );
    assert_eq!(
        ::std::mem::align_of::<SCRadix4Tree_>(),
        8usize,
        "Alignment of SCRadix4Tree_"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).head) as usize - ptr as usize },
        0usize,
        "Offset of field: SCRadix4Tree_::head"
    );
}
#[doc = " \\brief Structure for the radix tree"]
pub type SCRadix4Tree = SCRadix4Tree_;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SCRadix4Config_ {
    pub Free: ::std::option::Option<unsafe extern "C" fn(arg1: *mut ::std::os::raw::c_void)>,
    #[doc = " function pointer that is supplied by the user to free the user data\n  held by the user field of SCRadix4Node"]
    pub PrintData: ::std::option::Option<unsafe extern "C" fn(arg1: *mut ::std::os::raw::c_void)>,
}
#[test]
fn bindgen_test_layout_SCRadix4Config_() {
    const UNINIT: ::std::mem::MaybeUninit<SCRadix4Config_> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<SCRadix4Config_>(),
        16usize,
        "Size of SCRadix4Config_"
    );
    assert_eq!(
        ::std::mem::align_of::<SCRadix4Config_>(),
        8usize,
        "Alignment of SCRadix4Config_"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).Free) as usize - ptr as usize },
        0usize,
        "Offset of field: SCRadix4Config_::Free"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).PrintData) as usize - ptr as usize },
        8usize,
        "Offset of field: SCRadix4Config_::PrintData"
    );
}
pub type SCRadix4Config = SCRadix4Config_;
pub type SCRadix4ForEachNodeFunc = ::std::option::Option<
    unsafe extern "C" fn(
        node: *const SCRadix4Node,
        user_data: *mut ::std::os::raw::c_void,
        netmask: u8,
        data: *mut ::std::os::raw::c_void,
    ) -> ::std::os::raw::c_int,
>;
#[doc = " \\brief compare content of 2 user data entries\n  \\retval true equal\n  \\retval false not equal"]
pub type SCRadix4TreeCompareFunc = ::std::option::Option<
    unsafe extern "C" fn(
        ud1: *const ::std::os::raw::c_void,
        ud2: *const ::std::os::raw::c_void,
    ) -> bool,
>;
#[doc = " \\brief Structure for the node in the radix tree"]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SCRadix6Node_ {
    #[doc = " the key that has been stored in the tree"]
    pub prefix_stream: [u8; 16usize],
    #[doc = " holds bitmap of netmasks that come under this node in the tree"]
    pub masks: [u8; 17usize],
    #[doc = " the bit position where the bits differ in the nodes children.  Used\n to determine the path to be taken during a lookup"]
    pub bit: u8,
    #[doc = " bool to see if prefix_stream is filled"]
    pub has_prefix: bool,
    #[doc = " User data that has is associated with this key. We need a user\n data field for each netblock value possible since one ip can be associated\n with any of the 128 netblocks."]
    pub user_data: *mut RadixUserData,
    #[doc = " the left and the right children of a node"]
    pub left: *mut SCRadix6Node_,
    #[doc = " the left and the right children of a node"]
    pub right: *mut SCRadix6Node_,
    #[doc = " the parent node for this tree"]
    pub parent: *mut SCRadix6Node_,
}
#[test]
fn bindgen_test_layout_SCRadix6Node_() {
    const UNINIT: ::std::mem::MaybeUninit<SCRadix6Node_> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<SCRadix6Node_>(),
        72usize,
        "Size of SCRadix6Node_"
    );
    assert_eq!(
        ::std::mem::align_of::<SCRadix6Node_>(),
        8usize,
        "Alignment of SCRadix6Node_"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).prefix_stream) as usize - ptr as usize },
        0usize,
        "Offset of field: SCRadix6Node_::prefix_stream"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).masks) as usize - ptr as usize },
        16usize,
        "Offset of field: SCRadix6Node_::masks"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).bit) as usize - ptr as usize },
        33usize,
        "Offset of field: SCRadix6Node_::bit"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).has_prefix) as usize - ptr as usize },
        34usize,
        "Offset of field: SCRadix6Node_::has_prefix"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).user_data) as usize - ptr as usize },
        40usize,
        "Offset of field: SCRadix6Node_::user_data"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).left) as usize - ptr as usize },
        48usize,
        "Offset of field: SCRadix6Node_::left"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).right) as usize - ptr as usize },
        56usize,
        "Offset of field: SCRadix6Node_::right"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).parent) as usize - ptr as usize },
        64usize,
        "Offset of field: SCRadix6Node_::parent"
    );
}
#[doc = " \\brief Structure for the node in the radix tree"]
pub type SCRadix6Node = SCRadix6Node_;
#[doc = " \\brief Structure for the radix tree"]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SCRadix6Tree_ {
    #[doc = " the root node in the radix tree"]
    pub head: *mut SCRadix6Node,
}
#[test]
fn bindgen_test_layout_SCRadix6Tree_() {
    const UNINIT: ::std::mem::MaybeUninit<SCRadix6Tree_> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<SCRadix6Tree_>(),
        8usize,
        "Size of SCRadix6Tree_"
    );
    assert_eq!(
        ::std::mem::align_of::<SCRadix6Tree_>(),
        8usize,
        "Alignment of SCRadix6Tree_"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).head) as usize - ptr as usize },
        0usize,
        "Offset of field: SCRadix6Tree_::head"
    );
}
#[doc = " \\brief Structure for the radix tree"]
pub type SCRadix6Tree = SCRadix6Tree_;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SCRadix6Config_ {
    pub Free: ::std::option::Option<unsafe extern "C" fn(arg1: *mut ::std::os::raw::c_void)>,
    #[doc = " function pointer that is supplied by the user to free the user data\n  held by the user field of SCRadix6Node"]
    pub PrintData: ::std::option::Option<unsafe extern "C" fn(arg1: *mut ::std::os::raw::c_void)>,
}
#[test]
fn bindgen_test_layout_SCRadix6Config_() {
    const UNINIT: ::std::mem::MaybeUninit<SCRadix6Config_> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<SCRadix6Config_>(),
        16usize,
        "Size of SCRadix6Config_"
    );
    assert_eq!(
        ::std::mem::align_of::<SCRadix6Config_>(),
        8usize,
        "Alignment of SCRadix6Config_"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).Free) as usize - ptr as usize },
        0usize,
        "Offset of field: SCRadix6Config_::Free"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).PrintData) as usize - ptr as usize },
        8usize,
        "Offset of field: SCRadix6Config_::PrintData"
    );
}
pub type SCRadix6Config = SCRadix6Config_;
pub type SCRadix6ForEachNodeFunc = ::std::option::Option<
    unsafe extern "C" fn(
        node: *const SCRadix6Node,
        user_data: *mut ::std::os::raw::c_void,
        netmask: u8,
        data: *mut ::std::os::raw::c_void,
    ) -> ::std::os::raw::c_int,
>;
#[doc = " \\brief compare content of 2 user data entries\n  \\retval true equal\n  \\retval false not equal"]
pub type SCRadix6TreeCompareFunc = ::std::option::Option<
    unsafe extern "C" fn(
        ud1: *const ::std::os::raw::c_void,
        ud2: *const ::std::os::raw::c_void,
    ) -> bool,
>;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SCSha256 {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SCSha1 {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SCMd5 {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SCSigOrderFunc_ {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SCDetectRequiresStatus {
    _unused: [u8; 0],
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SCFPSupportSMList_ {
    pub list_id: ::std::os::raw::c_int,
    pub priority: ::std::os::raw::c_int,
    pub next: *mut SCFPSupportSMList_,
}
#[test]
fn bindgen_test_layout_SCFPSupportSMList_() {
    const UNINIT: ::std::mem::MaybeUninit<SCFPSupportSMList_> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<SCFPSupportSMList_>(),
        16usize,
        "Size of SCFPSupportSMList_"
    );
    assert_eq!(
        ::std::mem::align_of::<SCFPSupportSMList_>(),
        8usize,
        "Alignment of SCFPSupportSMList_"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).list_id) as usize - ptr as usize },
        0usize,
        "Offset of field: SCFPSupportSMList_::list_id"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).priority) as usize - ptr as usize },
        4usize,
        "Offset of field: SCFPSupportSMList_::priority"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).next) as usize - ptr as usize },
        8usize,
        "Offset of field: SCFPSupportSMList_::next"
    );
}
pub type SCFPSupportSMList = SCFPSupportSMList_;
#[repr(u32)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum Base64Mode {
    Base64ModeRFC2045 = 0,
    Base64ModeStrict = 1,
    Base64ModeRFC4648 = 2,
}
pub type ByteBase = u8;
pub type ByteEndian = u8;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct JsonBuilder {
    _unused: [u8; 0],
}
#[doc = " A \"mark\" or saved state for a JsonBuilder object.\n\n The name is full, and the types are u64 as this object is used\n directly in C as well."]
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct JsonBuilderMark {
    pub position: u64,
    pub state_index: u64,
    pub state: u64,
}
#[test]
fn bindgen_test_layout_JsonBuilderMark() {
    const UNINIT: ::std::mem::MaybeUninit<JsonBuilderMark> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<JsonBuilderMark>(),
        24usize,
        "Size of JsonBuilderMark"
    );
    assert_eq!(
        ::std::mem::align_of::<JsonBuilderMark>(),
        8usize,
        "Alignment of JsonBuilderMark"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).position) as usize - ptr as usize },
        0usize,
        "Offset of field: JsonBuilderMark::position"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).state_index) as usize - ptr as usize },
        8usize,
        "Offset of field: JsonBuilderMark::state_index"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).state) as usize - ptr as usize },
        16usize,
        "Offset of field: JsonBuilderMark::state"
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SCDetectByteExtractData {
    pub local_id: u8,
    pub nbytes: u8,
    pub offset: i16,
    pub name: *const ::std::os::raw::c_char,
    pub flags: u16,
    pub endian: ByteEndian,
    pub base: ByteBase,
    pub align_value: u8,
    pub multiplier_value: u16,
    pub id: u16,
}
#[test]
fn bindgen_test_layout_SCDetectByteExtractData() {
    const UNINIT: ::std::mem::MaybeUninit<SCDetectByteExtractData> =
        ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<SCDetectByteExtractData>(),
        32usize,
        "Size of SCDetectByteExtractData"
    );
    assert_eq!(
        ::std::mem::align_of::<SCDetectByteExtractData>(),
        8usize,
        "Alignment of SCDetectByteExtractData"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).local_id) as usize - ptr as usize },
        0usize,
        "Offset of field: SCDetectByteExtractData::local_id"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).nbytes) as usize - ptr as usize },
        1usize,
        "Offset of field: SCDetectByteExtractData::nbytes"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).offset) as usize - ptr as usize },
        2usize,
        "Offset of field: SCDetectByteExtractData::offset"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).name) as usize - ptr as usize },
        8usize,
        "Offset of field: SCDetectByteExtractData::name"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).flags) as usize - ptr as usize },
        16usize,
        "Offset of field: SCDetectByteExtractData::flags"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).endian) as usize - ptr as usize },
        18usize,
        "Offset of field: SCDetectByteExtractData::endian"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).base) as usize - ptr as usize },
        19usize,
        "Offset of field: SCDetectByteExtractData::base"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).align_value) as usize - ptr as usize },
        20usize,
        "Offset of field: SCDetectByteExtractData::align_value"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).multiplier_value) as usize - ptr as usize },
        22usize,
        "Offset of field: SCDetectByteExtractData::multiplier_value"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).id) as usize - ptr as usize },
        24usize,
        "Offset of field: SCDetectByteExtractData::id"
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SCDetectTransformFromBase64Data {
    pub flags: u8,
    pub nbytes: u32,
    pub nbytes_str: *const ::std::os::raw::c_char,
    pub offset: u32,
    pub offset_str: *const ::std::os::raw::c_char,
    pub mode: Base64Mode,
}
#[test]
fn bindgen_test_layout_SCDetectTransformFromBase64Data() {
    const UNINIT: ::std::mem::MaybeUninit<SCDetectTransformFromBase64Data> =
        ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<SCDetectTransformFromBase64Data>(),
        40usize,
        "Size of SCDetectTransformFromBase64Data"
    );
    assert_eq!(
        ::std::mem::align_of::<SCDetectTransformFromBase64Data>(),
        8usize,
        "Alignment of SCDetectTransformFromBase64Data"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).flags) as usize - ptr as usize },
        0usize,
        "Offset of field: SCDetectTransformFromBase64Data::flags"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).nbytes) as usize - ptr as usize },
        4usize,
        "Offset of field: SCDetectTransformFromBase64Data::nbytes"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).nbytes_str) as usize - ptr as usize },
        8usize,
        "Offset of field: SCDetectTransformFromBase64Data::nbytes_str"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).offset) as usize - ptr as usize },
        16usize,
        "Offset of field: SCDetectTransformFromBase64Data::offset"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).offset_str) as usize - ptr as usize },
        24usize,
        "Offset of field: SCDetectTransformFromBase64Data::offset_str"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).mode) as usize - ptr as usize },
        32usize,
        "Offset of field: SCDetectTransformFromBase64Data::mode"
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SCSigTableElmt {
    pub name: *const ::std::os::raw::c_char,
    pub desc: *const ::std::os::raw::c_char,
    pub url: *const ::std::os::raw::c_char,
    pub flags: u16,
    pub Setup: ::std::option::Option<
        unsafe extern "C" fn(
            de: *mut ::std::os::raw::c_void,
            s: *mut ::std::os::raw::c_void,
            raw: *const ::std::os::raw::c_char,
        ) -> ::std::os::raw::c_int,
    >,
    pub Free: ::std::option::Option<
        unsafe extern "C" fn(de: *mut ::std::os::raw::c_void, ptr: *mut ::std::os::raw::c_void),
    >,
    pub AppLayerTxMatch: ::std::option::Option<
        unsafe extern "C" fn(
            de: *mut ::std::os::raw::c_void,
            f: *mut ::std::os::raw::c_void,
            flags: u8,
            state: *mut ::std::os::raw::c_void,
            tx: *mut ::std::os::raw::c_void,
            sig: *const ::std::os::raw::c_void,
            ctx: *const ::std::os::raw::c_void,
        ) -> ::std::os::raw::c_int,
    >,
}
#[test]
fn bindgen_test_layout_SCSigTableElmt() {
    const UNINIT: ::std::mem::MaybeUninit<SCSigTableElmt> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<SCSigTableElmt>(),
        56usize,
        "Size of SCSigTableElmt"
    );
    assert_eq!(
        ::std::mem::align_of::<SCSigTableElmt>(),
        8usize,
        "Alignment of SCSigTableElmt"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).name) as usize - ptr as usize },
        0usize,
        "Offset of field: SCSigTableElmt::name"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).desc) as usize - ptr as usize },
        8usize,
        "Offset of field: SCSigTableElmt::desc"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).url) as usize - ptr as usize },
        16usize,
        "Offset of field: SCSigTableElmt::url"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).flags) as usize - ptr as usize },
        24usize,
        "Offset of field: SCSigTableElmt::flags"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).Setup) as usize - ptr as usize },
        32usize,
        "Offset of field: SCSigTableElmt::Setup"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).Free) as usize - ptr as usize },
        40usize,
        "Offset of field: SCSigTableElmt::Free"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).AppLayerTxMatch) as usize - ptr as usize },
        48usize,
        "Offset of field: SCSigTableElmt::AppLayerTxMatch"
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct SCTransformTableElmt {
    pub name: *const ::std::os::raw::c_char,
    pub desc: *const ::std::os::raw::c_char,
    pub url: *const ::std::os::raw::c_char,
    pub flags: u16,
    pub Setup: ::std::option::Option<
        unsafe extern "C" fn(
            de: *mut ::std::os::raw::c_void,
            s: *mut ::std::os::raw::c_void,
            raw: *const ::std::os::raw::c_char,
        ) -> ::std::os::raw::c_int,
    >,
    pub Free: ::std::option::Option<
        unsafe extern "C" fn(de: *mut ::std::os::raw::c_void, ptr: *mut ::std::os::raw::c_void),
    >,
    pub Transform: ::std::option::Option<
        unsafe extern "C" fn(
            inspect_buf: *mut ::std::os::raw::c_void,
            options: *mut ::std::os::raw::c_void,
        ),
    >,
    pub TransformValidate: ::std::option::Option<
        unsafe extern "C" fn(
            content: *const u8,
            len: u16,
            context: *mut ::std::os::raw::c_void,
        ) -> bool,
    >,
}
#[test]
fn bindgen_test_layout_SCTransformTableElmt() {
    const UNINIT: ::std::mem::MaybeUninit<SCTransformTableElmt> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<SCTransformTableElmt>(),
        64usize,
        "Size of SCTransformTableElmt"
    );
    assert_eq!(
        ::std::mem::align_of::<SCTransformTableElmt>(),
        8usize,
        "Alignment of SCTransformTableElmt"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).name) as usize - ptr as usize },
        0usize,
        "Offset of field: SCTransformTableElmt::name"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).desc) as usize - ptr as usize },
        8usize,
        "Offset of field: SCTransformTableElmt::desc"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).url) as usize - ptr as usize },
        16usize,
        "Offset of field: SCTransformTableElmt::url"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).flags) as usize - ptr as usize },
        24usize,
        "Offset of field: SCTransformTableElmt::flags"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).Setup) as usize - ptr as usize },
        32usize,
        "Offset of field: SCTransformTableElmt::Setup"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).Free) as usize - ptr as usize },
        40usize,
        "Offset of field: SCTransformTableElmt::Free"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).Transform) as usize - ptr as usize },
        48usize,
        "Offset of field: SCTransformTableElmt::Transform"
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).TransformValidate) as usize - ptr as usize },
        56usize,
        "Offset of field: SCTransformTableElmt::TransformValidate"
    );
}
extern "C" {
    pub fn jb_new_object() -> *mut JsonBuilder;
}
extern "C" {
    pub fn jb_new_array() -> *mut JsonBuilder;
}
extern "C" {
    pub fn jb_clone(js: *mut JsonBuilder) -> *mut JsonBuilder;
}
extern "C" {
    pub fn jb_free(js: *mut JsonBuilder);
}
extern "C" {
    pub fn jb_capacity(jb: *mut JsonBuilder) -> usize;
}
extern "C" {
    pub fn jb_reset(jb: *mut JsonBuilder);
}
extern "C" {
    pub fn jb_open_object(js: *mut JsonBuilder, key: *const ::std::os::raw::c_char) -> bool;
}
extern "C" {
    pub fn jb_start_object(js: *mut JsonBuilder) -> bool;
}
extern "C" {
    pub fn jb_open_array(js: *mut JsonBuilder, key: *const ::std::os::raw::c_char) -> bool;
}
extern "C" {
    pub fn jb_set_string(
        js: *mut JsonBuilder, key: *const ::std::os::raw::c_char,
        val: *const ::std::os::raw::c_char,
    ) -> bool;
}
extern "C" {
    pub fn jb_set_string_from_bytes(
        js: *mut JsonBuilder, key: *const ::std::os::raw::c_char, bytes: *const u8, len: u32,
    ) -> bool;
}
extern "C" {
    pub fn jb_set_base64(
        js: *mut JsonBuilder, key: *const ::std::os::raw::c_char, bytes: *const u8, len: u32,
    ) -> bool;
}
extern "C" {
    pub fn jb_set_hex(
        js: *mut JsonBuilder, key: *const ::std::os::raw::c_char, bytes: *const u8, len: u32,
    ) -> bool;
}
extern "C" {
    pub fn jb_set_formatted(js: *mut JsonBuilder, formatted: *const ::std::os::raw::c_char)
        -> bool;
}
extern "C" {
    pub fn jb_append_object(jb: *mut JsonBuilder, obj: *const JsonBuilder) -> bool;
}
extern "C" {
    pub fn jb_set_object(
        js: *mut JsonBuilder, key: *const ::std::os::raw::c_char, val: *mut JsonBuilder,
    ) -> bool;
}
extern "C" {
    pub fn jb_append_string(js: *mut JsonBuilder, val: *const ::std::os::raw::c_char) -> bool;
}
extern "C" {
    pub fn jb_append_string_from_bytes(js: *mut JsonBuilder, bytes: *const u8, len: u32) -> bool;
}
extern "C" {
    pub fn jb_append_base64(js: *mut JsonBuilder, bytes: *const u8, len: u32) -> bool;
}
extern "C" {
    pub fn jb_append_uint(js: *mut JsonBuilder, val: u64) -> bool;
}
extern "C" {
    pub fn jb_append_float(js: *mut JsonBuilder, val: f64) -> bool;
}
extern "C" {
    pub fn jb_set_uint(js: *mut JsonBuilder, key: *const ::std::os::raw::c_char, val: u64) -> bool;
}
extern "C" {
    pub fn jb_set_int(js: *mut JsonBuilder, key: *const ::std::os::raw::c_char, val: i64) -> bool;
}
extern "C" {
    pub fn jb_set_float(js: *mut JsonBuilder, key: *const ::std::os::raw::c_char, val: f64)
        -> bool;
}
extern "C" {
    pub fn jb_set_bool(js: *mut JsonBuilder, key: *const ::std::os::raw::c_char, val: bool)
        -> bool;
}
extern "C" {
    pub fn jb_close(js: *mut JsonBuilder) -> bool;
}
extern "C" {
    pub fn jb_len(js: *const JsonBuilder) -> usize;
}
extern "C" {
    pub fn jb_ptr(js: *mut JsonBuilder) -> *const u8;
}
extern "C" {
    pub fn jb_get_mark(js: *mut JsonBuilder, mark: *mut JsonBuilderMark);
}
extern "C" {
    pub fn jb_restore_mark(js: *mut JsonBuilder, mark: *mut JsonBuilderMark) -> bool;
}

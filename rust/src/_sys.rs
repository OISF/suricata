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

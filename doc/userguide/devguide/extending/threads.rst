Threads
#######

Rust API
********

The ``suricata_ffi::thread`` module provides Rust wrappers for thread
lifecycle callbacks.

Thread Init Callback
====================

Register a callback with ``thread::register_init_callback`` to run code for
each Suricata thread as it is initialized. The callback receives a
``ThreadVars`` wrapper for the thread that has just been initialized.

The current Rust thread lifecycle API exposes an init callback only; there is
no Rust thread deinit callback.

.. code-block:: rust

   use suricata_ffi::thread::{self, ThreadVars};
   use suricata_ffi::SCLogNotice;

   fn on_thread_init(tv: &mut ThreadVars) {
       SCLogNotice!("thread initialized: {:p}", tv.as_ptr());
   }

   fn register_thread_callbacks() -> Result<(), &'static str> {
       thread::register_init_callback(on_thread_init)
   }

The wrapper accepts function items or closures that implement
``Fn(&mut ThreadVars) + Send + Sync + 'static`` and returns
``Result<(), &'static str>``. An error means the callback could not be
registered. Registered callbacks are kept for the Suricata process lifetime.

``ThreadVars`` carries a lifetime tied to the callback invocation, so the
borrow checker prevents it from being stored beyond the call. Rust callbacks
must not panic, as they are invoked across an FFI boundary.

Thread Storage
==============

``thread::ThreadStorage<T>`` provides typed, per-thread storage backed by
Suricata's thread storage API. Each registered slot holds an independent value
of type ``T`` for every thread.

Register a slot once during initialization with
``ThreadStorage::<T>::register``. Registration must happen before Suricata
finalizes its storage registration, which is the case during plugin
initialization.

.. code-block:: rust

   use suricata_ffi::thread::{self, ThreadStorage, ThreadVars};

   #[derive(Default)]
   struct ThreadState {
       flows: u64,
   }

   fn register(storage: ThreadStorage<ThreadState>) -> Result<(), &'static str> {
       thread::register_init_callback(move |tv| on_thread_init(storage, tv))
   }

Values are owned by Suricata's thread storage and are dropped automatically when
the thread's storage is freed.

Access the value for a thread through the ``ThreadVars`` wrapper. ``get`` takes
``&ThreadVars`` and returns ``Option<&T>``. ``get_mut`` takes ``&mut
ThreadVars`` and returns ``Option<&mut T>``. ``get_or_insert_with`` also takes
``&mut ThreadVars`` and returns ``Result<&mut T, _>``, inserting a value
produced by the closure if the slot is empty:

.. code-block:: rust

   fn on_thread_init(storage: ThreadStorage<ThreadState>, tv: &mut ThreadVars) {
       let _ = storage.get_or_insert_with(tv, ThreadState::default);
   }

   fn on_flow_init(storage: ThreadStorage<ThreadState>, tv: &mut ThreadVars) {
       if let Some(state) = storage.get_mut(tv) {
           state.flows += 1;
       }
   }

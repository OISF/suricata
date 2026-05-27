Threads
#######

Rust API
********

The ``suricata_ffi::thread`` module provides Rust wrappers for thread
lifecycle callbacks.

Thread Init Callback
====================

Register a callback with ``thread::register_init_callback`` to run code for
each Suricata thread as it is initialized. The callback receives a raw
``ThreadVars`` pointer for the thread that has just been initialized.

The current Rust thread lifecycle API exposes an init callback only; there is
no Rust thread deinit callback.

.. code-block:: rust

   use suricata_ffi::thread;
   use suricata_ffi::SCLogNotice;
   use suricata_sys::sys::ThreadVars;

   fn on_thread_init(tv: *mut ThreadVars) {
       SCLogNotice!("thread initialized: {:p}", tv);
   }

   fn register_thread_callbacks() -> Result<(), &'static str> {
       thread::register_init_callback(on_thread_init)
   }

The wrapper accepts function items or closures that implement
``Fn(*mut ThreadVars) + Send + Sync + 'static`` and returns
``Result<(), &'static str>``. An error means the callback could not be
registered. Registered callbacks are kept for the Suricata process lifetime.

The ``ThreadVars`` pointer is only valid for the duration of the callback
invocation and must not be stored. Rust callbacks must not panic.

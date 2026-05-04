Flow Life Cycle Callbacks
#########################

Flow lifecycle callbacks let plugins and library users observe when
Suricata initializes a flow, updates a flow with a packet, and finishes
with a flow.

These callbacks are useful for maintaining plugin state that follows the
lifetime of a Suricata flow. For example, a plugin can allocate per-flow
state from the init callback, update it as packets are seen, and perform
final accounting from the finish callback.

C API
*****

Flow Init Callback
==================

The init callback is called when Suricata initializes a flow.

.. literalinclude:: ../../../../src/flow-callbacks.h
   :language: c
   :start-at: /** \brief Function type for flow initialization callbacks.
   :end-at: typedef void (*SCFlowInitCallbackFn)(ThreadVars *tv, Flow *f, const Packet *p, void *user);

Register an init callback with ``SCFlowRegisterInitCallback``.

.. literalinclude:: ../../../../src/flow-callbacks.h
   :language: c
   :start-at: /** \brief Register a flow init callback.
   :end-at: bool SCFlowRegisterInitCallback(SCFlowInitCallbackFn fn, void *user);

Flow Update Callback
====================

The update callback is called when Suricata updates a flow with a packet.

.. literalinclude:: ../../../../src/flow-callbacks.h
   :language: c
   :start-at: /** \brief Function type for flow update callbacks.
   :end-at: typedef void (*SCFlowUpdateCallbackFn)(ThreadVars *tv, Flow *f, Packet *p, void *user);

Register an update callback with ``SCFlowRegisterUpdateCallback``.

.. literalinclude:: ../../../../src/flow-callbacks.h
   :language: c
   :start-at: /** \brief Register a flow update callback.
   :end-at: bool SCFlowRegisterUpdateCallback(SCFlowUpdateCallbackFn fn, void *user);

Flow Finish Callback
====================

The finish callback is called when Suricata is done with a flow.

.. literalinclude:: ../../../../src/flow-callbacks.h
   :language: c
   :start-at: /** \brief Function type for flow finish callbacks.
   :end-at: typedef void (*SCFlowFinishCallbackFn)(ThreadVars *tv, Flow *f, void *user);

Register a finish callback with ``SCFlowRegisterFinishCallback``.

.. code-block:: c

   bool SCFlowRegisterFinishCallback(SCFlowFinishCallbackFn fn, void *user);

Example
=======

.. code-block:: c

   static void ExampleFlowInit(ThreadVars *tv, Flow *f, const Packet *p, void *user)
   {
       SCLogNotice("flow initialized: %p", f);
   }

   static void ExampleFlowUpdate(ThreadVars *tv, Flow *f, Packet *p, void *user)
   {
       SCLogNotice("flow updated: %p packet: %p", f, p);
   }

   static void ExampleFlowFinish(ThreadVars *tv, Flow *f, void *user)
   {
       SCLogNotice("flow finished: %p", f);
   }

   static void ExampleInit(void)
   {
       SCFlowRegisterInitCallback(ExampleFlowInit, NULL);
       SCFlowRegisterUpdateCallback(ExampleFlowUpdate, NULL);
       SCFlowRegisterFinishCallback(ExampleFlowFinish, NULL);
   }

Rust API
********

In Rust, use the ``suricata_ffi::flow`` module:

- ``flow::register_init_callback``
- ``flow::register_update_callback``
- ``flow::register_finish_callback``

The Rust wrappers register closures or function items and return
``Result<(), &'static str>``.

.. code-block:: rust

   use suricata_ffi::flow::{self, Flow, Packet, ThreadVars};
   use suricata_ffi::SCLogNotice;

   fn flow_init(_tv: *mut ThreadVars, f: *mut Flow, _p: *const Packet) {
       SCLogNotice!("flow initialized: {:p}", f);
   }

   fn flow_update(_tv: *mut ThreadVars, f: *mut Flow, p: *mut Packet) {
       SCLogNotice!("flow updated: {:p} packet: {:p}", f, p);
   }

   fn flow_finish(_tv: *mut ThreadVars, f: *mut Flow) {
       SCLogNotice!("flow finished: {:p}", f);
   }

   fn register_flow_callbacks() -> Result<(), &'static str> {
       flow::register_init_callback(flow_init)?;
       flow::register_update_callback(flow_update)?;
       flow::register_finish_callback(flow_finish)?;
       Ok(())
   }

The raw pointers passed into callbacks are only valid for the duration
of the callback invocation and must not be stored. Rust callbacks must
not panic.

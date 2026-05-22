Flow Storage
############

Rust API
********

Rust plugins can attach typed state to flows with
``suricata_ffi::flow::FlowStorage<T>``. A storage slot is registered once and
can then be used from flow callbacks to read or update per-flow state.

The storage slot must be registered before Suricata finalizes storage
registration, typically during plugin initialization.

``FlowStorage<T>`` owns values inserted through it. Values are dropped
automatically when Suricata frees the corresponding flow storage entry.

.. code-block:: rust

   use suricata_ffi::flow::{self, Flow, FlowStorage};
   use suricata_ffi::packet::Packet;
   use suricata_ffi::threadvars::ThreadVars;

   #[derive(Default)]
   struct State {
       packets: u64,
   }

   fn flow_update(
       _tv: ThreadVars<'_>, mut f: Flow<'_>, p: Option<Packet<'_>>,
       storage: FlowStorage<State>,
   ) {
       if let Ok(state) = storage.get_or_insert_with(&mut f, State::default) {
           if p.is_some() {
               state.packets += 1;
           }
       }
   }

   fn register_flow_callbacks() -> Result<(), &'static str> {
       let storage = FlowStorage::<State>::register("example-state")?;
       flow::register_update_callback(move |tv, f, p| {
           flow_update(tv, f, p, storage)
       })?;
       Ok(())
   }

Available methods
=================

``FlowStorage::<T>::register(name)``
   Register a typed flow storage slot.

``get(&flow)``
   Return ``Some(&T)`` if a value is stored on the flow.

``get_or_insert_with(&mut flow, init)``
   Return the stored value, inserting ``init()`` if the slot is empty.

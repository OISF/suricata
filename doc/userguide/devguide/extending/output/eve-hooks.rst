EVE Hooks
#########

The EVE output provides a callback for additional data to be added to
an EVE record before it is written.

It is important to note that it does not allow for modification of the
EVE record due to the append only nature of Suricata's EVE output.

C API
*****

Registration
============

In C, registering the callback is done with ``SCEveRegisterCallback``.

.. literalinclude:: ../../../../../src/output-eve.h
   :language: c
   :start-at: /** \brief Register a callback for adding extra information to EVE
   :end-at: );

Callback
========

The callback function is provided with an open ``SCJsonBuilder``
instance just before being closed out with a final ``}``. Additional
fields can be added with the ``SCJsonBuilder`` API.

.. literalinclude:: ../../../../../src/output-eve.h
   :language: c
   :start-at: /** \brief Function type for EVE callbacks
   :end-at: );

Example
=======

For a real-life C example, see the ``ndpi`` plugin included in the
Suricata source.

That example demonstrates:

- Registering an EVE callback during plugin initialization
- Using thread-local storage to maintain state
- Adding protocol-specific information to EVE records
- Properly checking for NULL pointers before accessing data

Rust API
********

In Rust, use ``suricata_ffi::eve::register_callback``. This wraps the C
API and lets the callback be registered as a Rust closure instead of a C
function pointer plus ``user`` pointer.

The closure receives:

- ``tv``: the ``ThreadVars`` for the thread performing the logging
- ``p``: the ``Packet``, if available
- ``f``: the ``Flow``, if available
- ``jb``: a Rust ``JsonBuilder`` wrapper for the current EVE record

Unlike the C API, the Rust callback returns ``Result<(), Error>``. If it
returns ``Err``, any JSON emitted by that callback is discarded.

.. code-block:: rust

   use suricata_ffi::eve;

   eve::register_callback(|_tv, _p, _f, jb| {
       jb.open_object("my_plugin")?;
       jb.set_string("key", "value")?;
       jb.close()?;
       Ok(())
   }).expect("failed to register EVE callback");

The Rust callback is invoked at the same point, but it receives a
``JsonBuilder`` wrapper instead of a raw ``SCJsonBuilder`` pointer.

The raw pointers passed into the callback are only valid for the
duration of the callback and must not be stored. The callback must also
not panic.

This API is safe for library and plugins.

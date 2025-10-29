EVE Hooks
#########

The EVE output provides a callback for additional data to be added to
an EVE record before it is written.

It is important to note that it does not allow for modification of the
EVE record due to the append only nature of Suricata's EVE output.

Registration
************

Registering the callback is done with ``SCEveRegisterCallback``.

.. literalinclude:: ../../../../../src/output-eve.h
   :language: c
   :start-at: /** \brief Register a callback for adding extra information to EVE
   :end-at: );

Callback
********

The callback function is provided with an open ``SCJsonBuilder``
instance just before being closed out with a final ``}``. Additional
fields can be added with the ``SCJsonBuilder`` API.

.. literalinclude:: ../../../../../src/output-eve.h
   :language: c
   :start-at: /** \brief Function type for EVE callbacks
   :end-at: );

Example
*******

For a real-life example, see the ``ndpi`` plugin included in the
Suricata source.

The example demonstrates:

- Registering an EVE callback during plugin initialization
- Using thread-local storage to maintain state
- Adding protocol-specific information to EVE records
- Properly checking for NULL pointers before accessing data

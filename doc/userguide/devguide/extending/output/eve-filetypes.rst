EVE Filetypes
#############

Introduction
************

The Suricata EVE/JSON output supports filetypes to extend how
EVE records are processed and delivered. Custom filetypes
provide alternatives to standard file output by implementing a
file-like interface that Suricata can write to. These filetypes can
send events to databases, sockets, or other destinations, and can even
perform custom processing on the output before storing it.

EVE Filetype Life Cycle
***********************

The life-cycle of an EVE filetype along with the callbacks are
discussed in ``output-eve.h``:

.. literalinclude:: ../../../../../src/output-eve.h
   :language: c
   :start-at: /** \brief Structure used to define an EVE output
   :end-at: } SCEveFileType;

Threading Considerations
************************

It is the user's Suricata EVE output configuration that enables
multi-threaded logging, not the filetype. So all filetypes should be
designed to be thread safe.

If your filetype can absolutely not be made thread safe, it would be
best to error out on initialization. This can be done during the
filetype initialization:

.. code-block:: c

   static int MyFiletypeInit(const SCConfNode *node, const bool threaded, void **data)
   {
       if (threaded) {
           FatalError("EVE filetype does not support threaded logging.");
       }

       /* Continue with initialization. */
   }

Write Considerations
********************

The ``Write`` callback is called in a packet processing thread so any
blocking (other than writing to a file) should be avoided. If writing
to a blocking resource it is recommended to copy the buffer into
another thread for further processing to avoid packet loss.

Registration
************

Registering an EVE filetype requires registering the filetype
early in the Suricata start-up or lifecycle, or if a plugin, in the
plugin initialization function.

.. code-block:: c

   SCEveFileType *filetype = SCCalloc(1, sizeof(SCEveFileType));

   filetype->name = "my-custom-filetype";
   filetype->Init = FiletypeInit;
   filetype->Deinit = FiletypeDeinit;
   filetype->ThreadInit = FiletypeThreadInit;
   filetype->ThreadDeinit = FiletypeThreadDeinit;
   filetype->Write = FiletypeWrite;

   if (!SCRegisterEveFileType(filetype)) {
       FatalError("Failed to register EVE filetype");
   }                                                                     		

Then to use this filetype, set the ``filetype`` in your
``suricata.yaml`` ``eve-log`` configuration to the name of the
filetype:

.. code-block:: yaml

   outputs:
     - eve-log:
         enabled: true
         filetype: my-custom-filetype

Examples
********

Suricata built-ins:

* ``null``: see ``output-eve-null.c`` in the Suricata source code
* ``syslog``: see ``output-eve-syslog.c`` in the Suricata source code

Plugin:

* The Suricata source code contains an example as a plugin, see:
  ``examples/plugins/c-json-filetype``.

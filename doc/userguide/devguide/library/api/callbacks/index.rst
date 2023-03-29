Callbacks
=========

The library allows to register callbacks to be invoked for different kind of events.
The callback signatures and the structs representing the various events can be found in the
*util-callbacks.h* and *util-events.h* headers respectively.

Notice that registering a callback automatically enables it in the library configuration.
Alternatively, the callbacks can be configured from a YAML file with the same syntax used by the
suricata binary for the EVE output module.

The currently supported events are described in detail in the following sections.

.. toctree::
   :maxdepth: 2

   alert
   fileinfo
   flow
   flowsnip
   http
   nta
   reject
   signature
   stats
   log

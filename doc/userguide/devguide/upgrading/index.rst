Upgrading
=========

Upgrading 8.0 to 9.0
--------------------

Alert Logging
~~~~~~~~~~~~~

Alert logging is done by iterating the `PacketAlert` entries in `Packet::alerts`. In 9.0
it is important to check the `PacketAlert::action` field for the `ACTION_ALERT` flag. If
this flag is not set, no alert should be generated. This is to support the `pass`-rule
usecase better.


Upgrading 7.0 to 8.0
--------------------

EVE File Types
~~~~~~~~~~~~~~

- The ``ThreadInit`` function will now be called when in *threaded*
  and *non-threaded* modes. This simplifies the initialization for EVE
  filetypes as they can use the same flow of execution for both
  modes. To upgrade, either remove the call to ``ThreadInit`` from
  ``Init``, or move per-thread setup code from ``Init`` to
  ``ThreadInit``.
- Many of the function arguments to the callbacks have been made
  ``const`` where it made sense.

Please see the latest example EVE filetype plugin for an up to date
example.


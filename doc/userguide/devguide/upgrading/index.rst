Upgrading
=========

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


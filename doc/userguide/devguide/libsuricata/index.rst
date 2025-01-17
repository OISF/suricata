.. _libsuricata:

LibSuricata and Plugins
=======================

Using Suricata as a Library
---------------------------

The ability to turn Suricata into a library that can be utilized in other tools
is currently a work in progress, tracked by Redmine Ticket #2693:
https://redmine.openinfosecfoundation.org/issues/2693.

Plugins
-------

A related work are Suricata plugins, also in progress and tracked by Redmine
Ticket #4101: https://redmine.openinfosecfoundation.org/issues/4101.

Plugins can be used by modifying suricata.yaml ``plugins`` section to include
the path of the dynamic library to load.

Plugins should export a ``SCPluginRegister`` function that will be the entry point
used by Suricata.

Application-layer plugins
~~~~~~~~~~~~~~~~~~~~~~~~~

Application layer plugins can be added as demonstrated by example
https://github.com/OISF/suricata/blob/master/examples/plugins/altemplate/

The plugin code contains the same files as an application layer in the source tree:
- alname.rs
- detect.rs
- lib.rs
- log.rs
- parser.rs

These files will have different ``use`` statements, targetting the suricata crate.

And the plugin contains also additional files:
- plugin.rs : defines the entry point of the plugin ``SCPluginRegister``

``SCPluginRegister`` should register callback that should then call ``SCPluginRegisterAppLayer``
passing a ``SCAppLayerPlugin`` structure to suricata.
It should also call ``suricata::plugin::init();`` to ensure the plugin has initialized
its value of the Suricata Context, a structure needed by rust, to call some C functions,
that cannot be found at compile time because of circular dependencies, and are therefore
resolved at runtime.

This ``SCAppLayerPlugin`` begins by a version number ``SC_PLUGIN_API_VERSION`` for runtime compatibility
between Suricata and the plugin.

Known limitations are:

- Plugins can only use simple logging as defined by ``EveJsonSimpleTxLogFunc``
  without suricata.yaml configuration, see https://github.com/OISF/suricata/pull/11160
- Keywords cannot use validate callbacks, see https://redmine.openinfosecfoundation.org/issues/5634
- Plugins cannot have keywords matching on mulitple protocols (like ja4),
  see https://redmine.openinfosecfoundation.org/issues/7304

.. attention:: A pure rust plugin needs to be compiled with ``RUSTFLAGS=-Clink-args=-Wl,-undefined,dynamic_lookup``

This is because the plugin will link dynamically at runtime the functions defined in Suricata runtime.
You can define this rust flags in a ``.cargo/config.toml`` file.
Lua Libraries
=============

Suricata provides Lua extensions, or libraries to Lua scripts with the
``require`` keyword. These extensions are particularly important in
Lua rules as Lua rules are executed in a restricted sandbox
environment without access to additional modules.

.. toctree::

   base64
   dns
   flowlib
   flowvar
   hashlib
   http
   packetlib
   rule
   ssh
   ja3

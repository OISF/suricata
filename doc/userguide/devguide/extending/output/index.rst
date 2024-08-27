Output
======

Low Level Logging
-----------------

Suricata's alert, protocol, and other types of output are built up
from a set of low level loggers. These loggers include:

- Packet logging (alerts)
- Flow logging
- Transaction logging (application layer)
- File information logging
- File data logging (file extraction)
- Statistics

These low level logging facilities are used to build up Suricata's
logging include EVE, but they can also be hooked into by plugins or
applications using Suricata as a library.

.. note:: At this time only a C API exists to hook into the low level
          logging functions.

The Suricata source code contains an example plugin demonstrating how
to hook into some of these APIs. See
https://github.com/OISF/suricata/blob/master/examples/plugins/c-custom-loggers/custom-logger.c.

Packet Logging
~~~~~~~~~~~~~~

Packet loggers can be registered with the
``SCOutputRegisterPacketLogger`` function:

.. literalinclude:: ../../../../../src/output-packet.h
   :language: c
   :start-at: /** \brief Register a packet logger
   :end-at: );

Flow Logging
~~~~~~~~~~~~

Flow loggers can be registered with the ``SCOutputRegisterFlowLogger``
function:

.. literalinclude:: ../../../../../src/output-flow.h
   :language: c
   :start-at: /** \brief Register a flow logger
   :end-at: );

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
https://github.com/OISF/suricata/blob/main/examples/plugins/c-custom-loggers/custom-logger.c.

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

Transaction Logging
~~~~~~~~~~~~~~~~~~~

Transaction logger can be registered with the
``SCOutputRegisterTxLogger`` function:

.. attention:: Transaction loggers cannot be registered from a plugin
               at this time, see
               https://redmine.openinfosecfoundation.org/issues/7236
               for more information.

.. literalinclude:: ../../../../../src/output-tx.h
   :language: c
   :start-at: /** \brief Register a transaction logger
   :end-at: );

Stream Logging
~~~~~~~~~~~~~~

Stream logging allows for the logging of streaming data such as TCP
reassembled data and HTTP body data. The provided log function will be
called each time a new chunk of data is available.

Stream loggers can be registered with the
``SCOutputRegisterStreamingLogger`` function:

.. literalinclude:: ../../../../../src/output-streaming.h
   :language: c
   :start-at: /** \brief Register a streaming logger
   :end-at: );

File Logging
~~~~~~~~~~~~

File loggers can be registered with the ``SCOutputRegisterFileLogger``
function:

.. literalinclude:: ../../../../../src/output-file.h
   :language: c
   :start-at: /** \brief Register a file logger
   :end-at: );

File-data Logging
~~~~~~~~~~~~~~~~~

File-data loggers can be registered with the
``SCOutputRegisterFileDataLogger`` function:

.. literalinclude:: ../../../../../src/output-filedata.h
   :language: c
   :start-at: /** \brief Register a file-data logger
   :end-at: );

Log
###

The ``suricata.log`` Lua library exposes the Suricata application
logging functions to Lua scripts. These are equivalant to
``SCLogNotice``, ``SCLogError``, etc, in the Suricata source.

In Suricata, the logging priority order is:

* Error
* Warning
* Notice
* Info
* Perf
* Config
* Debug

.. note:: Debug logging will only work if Suricata was compiled with
          ``--enable-debug``.

Setup
*****

To use the logging functions, first require the module::

    local logger = require("suricata.log")

Functions
*********

``info``
========

Log an informational message::

  logger.info("Processing HTTP request")

This is equivalent to ``SCLogInfo``.

``notice``
==========

Log a notice message::

  logger.notice("Unusual pattern detected")

This is equivalent to ``SCLogNotice``.

``warning``
===========

Log a warning message::

  logger.warning("Connection limit approaching")

This is equivalent to ``SCLogWarning``.

``error``
=========

Log an error message::

  logger.error("Failed to parse data")

This is equivalent to ``SCLogError``.

``debug``
=========

Log a debug message (only visible when debug logger.ing is enabled)::

  logger.debug("Variable value: " .. tostring(value))

This is equivalent to ``SCLogDebug``.

``config``
==========

Log a configuration-related message::

  logger.config("Loading configuration from " .. filename)

This is equivalent to ``SCLogConfig``.

``perf``
========

Log a performance-related message::

  logger.perf("Processing took " .. elapsed .. " seconds")

This is equivalent to ``SCLogPerf``.

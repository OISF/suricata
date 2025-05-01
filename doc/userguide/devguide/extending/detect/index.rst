Detection
#########

Rate Filter Callback
********************

A callback can be registered for any signature hit whose action has
been modified by the rate filter. This allows for the user to modify
the action, if needed using their own custom logic.

For an example, see ``examples/lib/custom/main.c`` in the Suricata
source code.

The Callback
============

The callback function will be called with the packet, signature
details (sid, gid, rev), original action, the new action, and a user
provided argument. It will only be called if the Suricata rate filter
modified the action:

.. literalinclude:: ../../../../../src/detect.h
   :language: c
   :start-at:  * \brief Function type for rate filter callback.
   :end-at: );
   :prepend: /**

Callback Registration
=====================

To register the rate filter callback, use the
``SCDetectEngineRegisterRateFilterCallback`` function with your
callback and a user provided argument which will be provided to the
callback.

.. literalinclude:: ../../../../../src/detect.h
   :language: c
   :start-at:  * \brief Register a callback when a rate_filter
   :end-at: );
   :prepend: /**

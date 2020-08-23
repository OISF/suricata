Rule Reloads
============

Suricata can reload the rules without restarting. This way, there
is minimal service disruption.

This works by sending Suricata a signal or by using the unix socket. When Suricata is told to reload the rules these are the basic steps it takes:

* Load new config to update rule variables and values.
* Load new rules
* Construct new detection engine
* Swap old and new detection engines
* Make sure all threads are updated
* Free old detection engine

Suricata will continue to process packets normally during this process. Keep in mind though, that the system should have enough memory for both detection engines.

Signal::

  kill -USR2 $(pidof suricata)

There are two methods available when using the Unix socket.

Blocking reload ::

  suricatasc -c reload-rules

Non blocking reload ::

  suricatasc -c ruleset-reload-nonblocking

It is also possible to get information about the last reload via dedicated commands. See :ref:`standard-unix-socket-commands` for more information.

Rule Reloads
============

Suricata can be told to reloads it's rules without restarting.

This works by sending Suricata a signal or by using the unix socket. When Suricata is told to reload the rules these are the basic steps it takes:

* Load new config
* Load new rules
* Construct new detection engine
* Swap old and new detection engines
* Make sure all threads are updated
* Free old detection engine

Suricata will continue to process packets normally during this process. Keep in mind though, that the system should have enough memory for both detection engines.

Signal::

  kill -USR2 $(pidof suricata)

Unix socket::

  suricatasc -c reload-rules

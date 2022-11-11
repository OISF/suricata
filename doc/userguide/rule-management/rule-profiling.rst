Rules Profiling
===============

If Suricata is built with the --enable-profiling-rules then the ruleset profiling
can be activated on demand from the unix socket and dumped from it.

To start profiling ::

 surictasc -c ruleset-profile-start

To stop profiling ::

 surictasc -c ruleset-profile-stop

To dump profiling ::

 suricatasc -c ruleset-profile

A typical scenario to get rules performance would be ::

 surictasc -c ruleset-profile-start
 sleep 30
 surictasc -c ruleset-profile-stop
 suricatasc -c ruleset-profile

On busy systems, using the sampling capability to capture performance
on a subset of packets can be obtained via the `sample-rate` variable
in the `profiling` section.

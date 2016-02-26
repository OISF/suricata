Suricata
========

SYNOPSIS
--------

**suricata** [OPTIONS] [BPF FILTER]

DESCRIPTION
-----------

Suricata is a high performance Network IDS, IPS and Network Security
Monitoring engine. Open Source and owned by a community run non-profit
foundation, the Open Information Security Foundation (OISF).

OPTIONS
-------

.. option:: -c <path>

   Path to configuration file.

.. option:: -T

   Test configuration.

.. option:: -i <device or IP address>

   Run in PCAP live mode on provided interface.

.. option:: -F <bpf filter file>

   Use BPF filter from file.

.. option:: -r <path>

   Run in pcap offline mode reading files from pcap file.

.. option:: -q <queue id>

   Run inline of the NFQUEUE queue ID provided. May be provided
   multiple times.

.. option:: -s <path>

   Path to a signature file to load. Will be loaded in addition to the
   rule files specified in the configuration file.

.. option:: -S <path>

   Path to signature file to load exclusively. Signature files
   specified in the configuration file will not be loaded.

.. option:: -l <directory>

   Set log directory. Overrides the default-log-directory provided in
   the configuration file.
   
.. option:: -D

   Run as a daemon.

.. option:: -k [all|none]

   Force (all) the checksum check or disable (none) all checksum
   checks.

.. option:: -V

   Display version.

.. option:: -v[v]

   Increase the verbosity of logging. This is Suricata application
   logging, not event or NSM logging.

.. option:: -u

   Run the unit tests and exit. Requires that Suricata be compiled
   with *--enable-unittests*.

.. option:: -U, --unittest-filter=REGEX

   File the executed unit tests with a regular expression.

.. option:: --list-unittests

   List all unit tests.

.. option:: --fatal-unittests

   Enables fatal failure on a unit test error. Suricata will exit
   instead of continuuing more tests.

.. option:: --unittests-coverage

   Display unit test coverage report.

.. option:: --list-app-layer-protos

   List all supported application layer protocols.

.. option:: --list-keywords=[all|csv|<kword>]

   List all supported rule keywords.

.. option:: --list-runmodes

   List all supported run modes.

.. option:: --runmode <runmode>

   Run with a specific run mode. Run modes may be viewed with the
   *--list-runmodes* option. Usually one of *workers*, *autofp*, or
   *single*.

.. option:: --engine-analysis

   Print reports on analysis of different sections in the engine and
   exit. Please have a look at the conf parameter engine-analysis on
   what reports can be printed

.. option:: --pidfile <file>

   Write the process ID to file. Overrides the *pid-file* option in
   the configuration file and forces the file to be written when not
   running as a daemon.

.. option:: --init-errors-fatal

   Exit with a failure when errors are encountered loading signatures.

.. option:: --disable-detection

   Disable the detection engine.

.. option:: --dump-config

   Dump the configuration loaded from the configuration file to the
   terminal and exit.

.. option:: --build-info

   Display the build information the Suricata was built with.

.. option:: --pcap=<device>

   Run in PCAP mode. If no device is provided the interfaces
   provided in the *pcap* section of the configuration file will be
   used.

.. option:: --pcap-buffer-size=<size>

   Set the size of the PCAP buffer (0 - 2147483647).

.. option:: --af-packet=<device>

   Run in AF_PACKET mode. If no device is provided the interfaces
   provided in the *af-packet* section of the configuration file will be
   used.
	    
.. option:: --simulate-ips

   Force the engine into IPS mode. Useful for QA.

.. option:: --user=<user>

   Set the process user after initialization. Overrides the user
   provided in the *run-as* section of the configuration file.

.. option:: --group=<group>

   Set the process group to group after initialization. Overrides the
   group provided in the *run-as* section of the configuration file.

.. option:: --erf-in=<file>

   Run in offline mode reading the specific ERF file (Endace
   extensible record format).

.. option:: --unix-socket=<file>

   Use file as the Suricata unix control socket. Overrides the
   *filename* provided in the *unix-command* section of the
   configuration file.

.. option:: --set <name>=<value>

   Set a configuration value. Useful for overriding basic
   configuration parameters in the configuration. For example, to
   change the default log directory::

     --set default-log-dir=/var/tmp
     

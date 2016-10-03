Command Line Options
====================

.. toctree::

Suricata's command line options:

.. option:: -h

   Display a brief usage overview.

.. option:: -V

   Displays the version of Suricata.

.. option:: -c <path>

   Select suricata.yaml configuration file.

.. option::  -i <interface>

   After the -i option you can enter the interface card you would like
   to use to sniff packets from.  This option will try to use the best
   capture method available.

.. option:: -v

   The -v option enables more verbosity of Suricata's output. Supply
   multiple times for more verbosity.

.. option::  -r <filename.pcap>

   After the -r option you can enter the path to the pcap-file in
   which packets are recorded. That way you can inspect the packets in
   that file in the pcap/offline mode.

.. option:: -s <filename.rules>

   With the -s option you can set a file with signatures, which will
   be loaded together with the rules set in the yaml.

.. option:: -S <filename.rules>

   With the -S option you can set a file with signatures, which will
   be loaded exclusively, regardless of the rules set in the yaml.

.. option:: -l <directory>

   With the -l option you can set the default log directory. If you
   already have the default-log-dir set in yaml, it will not be used
   by Suricata if you use the -l option. It will use the log dir that
   is set with the -l option. If you do not set a directory with
   the -l option, Suricata will use the directory that is set in yaml.

.. option:: -D

   Normally if you run Suricata on your console, it keeps your console
   occupied. You can not use it for other purposes, and when you close
   the window, Suricata stops running.  If you run Suricata as deamon
   (using the -D option), it runs at the background and you will be
   able to use the console for other tasks without disturbing the
   engine running.

.. option:: --runmode <runmode>

   With the --runmode option you can set the runmode that you would
   like to use. This command line option can override the yaml
   runmode option.

   Runmodes are: workers, autofp and single.

For more information about runmodes see: :doc:`performance/runmodes`

.. option:: --build-info

   Gives an overview of the configure and build options that were
   supplied to Suricata's build process at compile time.

Capture Options
~~~~~~~~~~~~~~~

.. option:: --af-packet[=<device>]

   Enable capture of packet using AF_PACKET on Linux. If no device is
   supplied, the list of devices from the af-packet section in the
   yaml is used.

.. option:: --netmap[=<device>]

   Enable capture of packet using NETMAP on FreeBSD or Linux. If no
   device is supplied, the list of devices from the netmap section
   in the yaml is used.

Advanced Options
~~~~~~~~~~~~~~~~

.. option:: --dump-config

   Displays a list of key value pairs with Suricata's configuration.

.. option:: --set <key>=<value>

   Override any configuration option.

.. option:: --list-app-layer-protos

   List supported app layer protocols.

.. option:: --list-keywords[=all|csv|<kword>]

   List keywords implemented by the engine

.. option:: --list-runmodes

   The option --list-runmodes lists all possible runmodes.

Unit Tests
~~~~~~~~~~

Builtin unittests are only available if Suricata has been built with
--enable-unittests.

Running unittests does not take a configuration file. Use -l to supply
an output directory.

.. option:: -u

   With the -u option you can run unit tests to test Suricata's code.

.. option:: -U <regex>

   With the -U option you can select which of the unit tests you want
   to run. This option uses REGEX.  Example of use: suricata -u -U
   http

.. option:: --list-unittests

   The --list-unittests option shows a list with all possible unit
   tests.

.. option::  --fatal-unittests

   With the --fatal-unittests option you can run unit tests but it
   will stop immediately after one test fails so you can see directly
   where it went wrong.


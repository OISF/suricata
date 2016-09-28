Snort.conf to Suricata.yaml
===========================

This guide is meant for those who are familiar with Snort and the
snort.conf configuration format. This guide will provide a 1:1 mapping
between Snort and Suricata configuration wherever possible.

Variables
---------

snort.conf

::

  ipvar HOME_NET any
  ipvar EXTERNAL_NET any
  ...

  portvar HTTP_PORTS [80,81,311,591,593,901,1220,1414,1741,1830,2301,2381,2809,3128,3702,4343,4848,5250,7001,7145,7510,7777,7779,8000,8008,8014,8028,8080,8088,8090,8118,8123,8180,8181,8243,8280,8800,8888,8899,9000,9080,9090,9091,9443,9999,11371,55555]
  portvar SHELLCODE_PORTS !80
  ...

suricata.yaml

::


  vars:
    address-groups:

      HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
      EXTERNAL_NET: "!$HOME_NET"

    port-groups:
      HTTP_PORTS: "80"
      SHELLCODE_PORTS: "!80"

Note that Suricata can automatically detect HTTP traffic regardless of
the port it uses. So the HTTP_PORTS variable is not nearly as
important as it is with Snort, **if** you use a Suricata enabled
ruleset.

Decoder alerts
--------------

snort.conf

::

  # Stop generic decode events:
  config disable_decode_alerts

  # Stop Alerts on experimental TCP options
  config disable_tcpopt_experimental_alerts

  # Stop Alerts on obsolete TCP options
  config disable_tcpopt_obsolete_alerts

  # Stop Alerts on T/TCP alerts
  config disable_tcpopt_ttcp_alerts

  # Stop Alerts on all other TCPOption type events:
  config disable_tcpopt_alerts

  # Stop Alerts on invalid ip options
  config disable_ipopt_alerts

suricata.yaml

Suricata has no specific decoder options. All decoder related alerts
are controlled by rules. See #Rules below.

Checksum handling
-----------------

snort.conf

::

  config checksum_mode: all

suricata.yaml

Suricata's checksum handling works *on-demand*. The stream engine
checks TCP and IP checksum by default:

::

  stream:
    checksum-validation: yes      # reject wrong csums

Alerting on bad checksums can be done with normal rules. See #Rules,
decoder-events.rules specifically.

Various configs
---------------

Active response
~~~~~~~~~~~~~~~

snort.conf

::

  # Configure active response for non inline operation. For more information, see REAMDE.active
  # config response: eth0 attempts 2

suricata.yaml

Active responses are handled automatically w/o config if rules with
the "reject" action are used.

Dropping privileges
~~~~~~~~~~~~~~~~~~~

snort.conf

::


  # Configure specific UID and GID to run snort as after dropping privs. For more information see snort -h command line options
  #
  # config set_gid:
  # config set_uid:

Suricata

To set the user and group use the --user <username> and --group
<groupname> commandline options.

Snaplen
~~~~~~~

snort.conf

::

  # Configure default snaplen. Snort defaults to MTU of in use interface. For more information see README
  #
  # config snaplen:
  #

Suricata always works at full snap length to provide full traffic visibility.

Bpf
~~~

snort.conf

::

  # Configure default bpf_file to use for filtering what traffic reaches snort. For more information see snort -h command line options (-F)
  #
  # config bpf_file:
  #

suricata.yaml

BPF filters can be set per packet acquisition method, with the "bpf-filter: <file>" yaml option and in a file using the -F command line option.

For example:

::

  pcap:
    - interface: eth0
      #buffer-size: 16777216
      #bpf-filter: "tcp and port 25"
      #checksum-checks: auto
      #threads: 16
      #promisc: no
      #snaplen: 1518

Log directory
-------------

snort.conf

::

  # Configure default log directory for snort to log to.  For more information see snort -h command line options (-l)
  #
  # config logdir:

suricata.yaml

::

  default-log-dir: /var/log/suricata/

This value is overridden by the -l commandline option.

Packet acquisition
------------------

snort.conf

::

  # Configure DAQ related options for inline operation. For more information, see README.daq
  #
  # config daq: <type>
  # config daq_dir: <dir>
  # config daq_mode: <mode>
  # config daq_var: <var>
  #
  # <type> ::= pcap | afpacket | dump | nfq | ipq | ipfw
  # <mode> ::= read-file | passive | inline
  # <var> ::= arbitrary <name>=<value passed to DAQ
  # <dir> ::= path as to where to look for DAQ module so's

suricata.yaml

Suricata has all packet acquisition support built-in. It's
configuration format is very verbose.

::

  pcap:
    - interface: eth0
      #buffer-size: 16777216
      #bpf-filter: "tcp and port 25"
      #checksum-checks: auto
      #threads: 16
      #promisc: no
      #snaplen: 1518
  pfring:
  afpacket:
  nfq:
  ipfw:

Passive vs inline vs reading files is determined by how Suricata is
invoked on the command line.

Rules
-----

snort.conf:

In snort.conf a RULE_PATH variable is set, as well as variables for
shared object (SO) rules and preprocessor rules.

::

  var RULE_PATH ../rules
  var SO_RULE_PATH ../so_rules
  var PREPROC_RULE_PATH ../preproc_rules

  include $RULE_PATH/local.rules
  include $RULE_PATH/emerging-activex.rules
  ...

suricata.yaml:

In the suricata.yaml the default rule path is set followed by a list
of rule files. Suricata does not have a concept of shared object rules
or preprocessor rules. Instead of preprocessor rules, Suricata has
several rule files for events set by the decoders, stream engine, http
parser etc.

::

  default-rule-path: /etc/suricata/rules
  rule-files:
   - local.rules
   - emerging-activex.rules

The equivalent of preprocessor rules are loaded like normal rule files:

::

  rule-files:
   - decoder-events.rules
   - stream-events.rules
   - http-events.rules
   - smtp-events.rules

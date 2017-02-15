Interacting via Unix Socket
===========================

Introduction
------------

Suricata can listen to a unix socket and accept commands from the user. The
exchange protocol is JSON-based and the format of the message has been done
to be generic.

An example script called suricatasc is provided in the source and installed
automatically when installing/updating Suricata.

The unix socket is enabled by default if libjansson is available.

You need to have libjansson installed:
  
* libjansson4 - C library for encoding, decoding and manipulating JSON data
* libjansson-dev - C library for encoding, decoding and manipulating JSON data (dev)
* python-simplejson - simple, fast, extensible JSON encoder/decoder for Python
  
Debian/Ubuntu::
  
   apt-get install libjansson4 libjansson-dev python-simplejson

If libjansson is present on the system , unix socket will be compiled
in automatically.

The creation of the socket is managed by setting enabled to 'yes' or 'auto'
under unix-command in Suricata YAML configuration file:
  
::
  
  unix-command:
    enabled: yes
    #filename: custom.socket # use this to specify an alternate file

The ``filename`` variable can be used to set an alternate socket
filename. The filename is always relative to the local state base
directory.

Clients are implemented for some language and can be used as code
example to write custom scripts:

* Python: https://github.com/inliniac/suricata/blob/master/scripts/suricatasc/suricatasc.in (provided with suricata and used in this document)
* Perl: https://github.com/aflab/suricatac (a simple Perl client with interactive mode)
* C: https://github.com/regit/SuricataC (a unix socket mode client in C without interactive mode)

Commands in standard running mode
---------------------------------


The set of existing commands is the following:

* command-list: list available commands
* shutdown: this shutdown suricata
* iface-list: list interfaces where Suricata is sniffing packets
* iface-stat: list statistic for an interface
* help: alias of command-list
* version: display Suricata's version
* uptime: display Suricata's uptime
* running-mode: display running mode (workers, autofp, simple)
* capture-mode: display capture system used
* conf-get: get configuration item (see example below)
* dump-counters: dump Suricata's performance counters

You can access to these commands with the provided example script which
is named ``suricatasc``. A typical session with ``suricatasc`` will looks like:
  
::
  
  # suricatasc
  Command list: shutdown, command-list, help, version, uptime, running-mode, capture-mode, conf-get, dump-counters, iface-stat, iface-list, quit
  >>> iface-list
  Success: {'count': 2, 'ifaces': ['eth0', 'eth1']}
  >>> iface-stat eth0
  Success: {'pkts': 378, 'drop': 0, 'invalid-checksums': 0}
  >>> conf-get unix-command.enabled
  Success:
  "yes"

Commands on the cmd prompt
--------------------------

You can use suricatasc directly on the command prompt:
  
::

  
  root@debian64:~# suricatasc -c version
  {'message': '2.1beta2 RELEASE', 'return': 'OK'}
  root@debian64:~# 
  root@debian64:~# suricatasc -c uptime
  {'message': 35264, 'return': 'OK'}
  root@debian64:~#


**NOTE:**
You need to quote commands involving more than one argument:
  
::

  
  root@debian64:~# suricatasc -c "iface-stat eth0"
  {'message': {'pkts': 5110429, 'drop': 0, 'invalid-checksums': 0}, 'return': 'OK'}
  root@debian64:~#


Pcap processing mode
--------------------

This mode is one of main motivation behind this code. The idea is to
be able to ask to Suricata to treat different pcap files without
having to restart Suricata between the files. This provides you a huge
gain in time as you don’t need to wait for the signature engine to
initialize.

To use this mode, start suricata with your preferred YAML file and
provide the option ``--unix-socket`` as argument:
  
::
  
  suricata -c /etc/suricata-full-sigs.yaml --unix-socket

It is also possible to specify the socket filename as argument:
  
::
  
  suricata --unix-socket=custom.socket

In this last case, you will need to provide the complete path to the
socket to ``suricatasc``. To do so, you need to pass the filename as
first argument of ``suricatasc``:
  
::
  
  suricatasc custom.socket

Once Suricata is started, you can use the provided script
``suricatasc`` to connect to the command socket and ask for pcap
treatment:
  
::
  
  root@tiger:~# suricatasc
  >>> pcap-file /home/benches/file1.pcap /tmp/file1
  Success: Successfully added file to list
  >>> pcap-file /home/benches/file2.pcap /tmp/file2
  Success: Successfully added file to list

You can add multiple files without waiting the result: they will be
sequentially processed and the generated log/alert files will be put
into the directory specified as second arguments of the pcap-file
command. You need to provide absolute path to the files and directory
as suricata don’t know from where the script has been run.

To know how much files are waiting to get processed, you can do:
  
::
  
  >>> pcap-file-number
  Success: 3

To get the list of queued files, do:
  
::
  
  >>> pcap-file-list
  Success: {'count': 2, 'files': ['/home/benches/file1.pcap', '/home/benches/file2.pcap']}

To get current processed file:
  
::
  
  >>> pcap-current
  Success:
  "/tmp/test.pcap"

Build your own client
---------------------

The protocol is documented in the following page
https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Unix_Socket#Protocol

The following session show what is send (SND) and received (RCV) by
the server. Initial negotiation is the following:
  
::
  
  # suricatasc
  SND: {"version": "0.1"}
  RCV: {"return": "OK"}

Once this is done, command can be issued:
  
::
  
  >>> iface-list
  SND: {"command": "iface-list"}
  RCV: {"message": {"count": 1, "ifaces": ["wlan0"]}, "return": "OK"}
  Success: {'count': 1, 'ifaces': ['wlan0']}
  >>> iface-stat wlan0
  SND: {"command": "iface-stat", "arguments": {"iface": "wlan0"}}
  RCV: {"message": {"pkts": 41508, "drop": 0, "invalid-checksums": 0}, "return": "OK"}
  Success: {'pkts': 41508, 'drop': 0, 'invalid-checksums': 0}

In pcap-file mode, this gives:
  
::
  
  >>> pcap-file /home/eric/git/oisf/benches/sandnet.pcap /tmp/bench
  SND: {"command": "pcap-file", "arguments": {"output-dir": "/tmp/bench", "filename": "/home/eric/git/oisf/benches/sandnet.pcap"}}
  RCV: {"message": "Successfully added file to list", "return": "OK"}
  Success: Successfully added file to list
  >>> pcap-file-number
  SND: {"command": "pcap-file-number"}
  RCV: {"message": 1, "return": "OK"}
  >>> pcap-file-list
  SND: {"command": "pcap-file-list"}
  RCV: {"message": {"count": 1, "files": ["/home/eric/git/oisf/benches/sandnet.pcap"]}, "return": "OK"}
  Success: {'count': 1, 'files': ['/home/eric/git/oisf/benches/sandnet.pcap']}

There is one thing to be careful about: a suricata message is sent in
multiple send operations. This result in possible incomplete read on
client side. The worse workaround is to sleep a bit before trying a
recv call. An other solution is to use non blocking socket and retry a
recv if the previous one has failed. This method is used here:
source:scripts/suricatasc/suricatasc.in#L43

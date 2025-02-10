Interacting via Unix Socket
===========================

Introduction
------------

Suricata can listen to a unix socket and accept commands from the user. The
exchange protocol is JSON-based and the format of the message is generic.

An application called ``suricatasc`` is provided and installed
automatically when installing/updating Suricata.

The unix socket is always enabled by default.

The creation of the socket is managed by setting enabled to 'yes' or 'auto'
under unix-command in Suricata YAML configuration file: ::
  
  unix-command:
    enabled: yes
    #filename: custom.socket # use this to specify an alternate file

The ``filename`` variable can be used to set an alternate socket
filename. The filename is always relative to the local state base
directory.

Clients are implemented for some programming languages and can be used as code
example to write custom scripts:

* Rust: https://github.com/OISF/suricata/blob/master/rust/suricatasc (version provided in Suricata 8+)
* Python: https://github.com/OISF/suricata/blob/main-7.0.x/python/suricata/sc/suricatasc.py (Python version from older versions of Suricata)
* Perl: https://github.com/aflab/suricatac (a simple Perl client with interactive mode)
* C: https://github.com/regit/SuricataC (a Unix socket mode client in C without interactive mode)

.. _standard-unix-socket-commands:

Commands in standard running mode
---------------------------------

The ``suricatasc`` command should automatically be installed in the
same directory as the main ``suricata`` program.

The set of existing commands is the following:

* command-list: list available commands
* shutdown: shutdown Suricata
* iface-list: list interfaces where Suricata is sniffing packets
* iface-stat: list statistics for an interface
* help: alias of command-list
* version: display Suricata's version
* uptime: display Suricata's uptime
* running-mode: display running mode (workers, autofp, simple)
* capture-mode: display capture system used
* conf-get: get configuration item (see example below)
* dump-counters: dump Suricata's performance counters
* reopen-log-files: reopen log files (to be run after external log rotation)
* ruleset-reload-rules: reload ruleset and wait for completion
* ruleset-reload-nonblocking: reload ruleset and proceed without waiting
* ruleset-reload-time: return time of last reload
* ruleset-stats: display the number of rules loaded and failed
* ruleset-failed-rules: display the list of failed rules
* memcap-set: update memcap value of the specified item
* memcap-show: show memcap value of the specified item
* memcap-list: list all memcap values available
* reload-rules: alias of ruleset-reload-rules
* register-tenant-handler: register a tenant handler with the specified mapping
* unregister-tenant-handler: unregister a tenant handler with the specified mapping
* register-tenant: register tenant with a particular ID and filename
* unregister-tenant: unregister tenant with a particular ID
* reload-tenant: reload a tenant with specified ID and filename
* add-hostbit: add hostbit on a host IP with a particular bit name and time of expiry
* remove-hostbit: remove hostbit on a host IP with specified bit name
* list-hostbit: list hostbit for a particular host IP

A typical session with ``suricatasc`` looks like:

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

You can use ``suricatasc`` directly on the command prompt:

::

  root@debian64:~# suricatasc -c version
  {'message': '5.0.3 RELEASE', 'return': 'OK'}
  root@debian64:~# 
  root@debian64:~# suricatasc -c uptime
  {'message': 35264, 'return': 'OK'}
  root@debian64:~#


**NOTE:**
You need to quote commands with more than one argument:

::

  root@debian64:~# suricatasc -c "iface-stat eth0"
  {'message': {'pkts': 5110429, 'drop': 0, 'invalid-checksums': 0}, 'return': 'OK'}
  root@debian64:~#


PCAP processing mode
--------------------

This mode is one of main motivations behind this code. The idea is to
be able to provide different pcap files to Suricata without
having to restart Suricata for each file. This saves time since
you don't need to wait for the signature engine to initialize.

To use this mode, start Suricata with your preferred configuration YAML file and
provide the option ``--unix-socket`` as argument::
  
  suricata -c /etc/suricata-full-sigs.yaml --unix-socket

It is also possible to specify the socket filename as an argument::
  
  suricata --unix-socket=custom.socket

In this last case, you will need to provide the complete path to the
socket to ``suricatasc``. To do so, you need to pass the filename as
first argument of ``suricatasc``: ::

  suricatasc custom.socket

Once Suricata is started, you can use ``suricatasc`` to connect to the
command socket and provide different pcap files: ::
  
  root@tiger:~# suricatasc
  >>> pcap-file /home/benches/file1.pcap /tmp/file1
  Success: Successfully added file to list
  >>> pcap-file /home/benches/file2.pcap /tmp/file2
  Success: Successfully added file to list
  >>> pcap-file-continuous /home/pcaps /tmp/dirout
  Success: Successfully added file to list

You can add multiple files without waiting for each to be processed; they will be
sequentially processed and the generated log/alert files will be put
into the directory specified as second argument of the pcap-file
command. You need to provide an absolute path to the files and directory
as Suricata doesn't know from where the script has been run. If you pass
a directory instead of a file, all files in the directory will be processed. If
using ``pcap-file-continuous`` and passing in a directory, the directory will
be monitored for new files being added until you use ``pcap-interrupt`` or
delete/move the directory.

To display  how many files are waiting to get processed, you can do: ::
  
  >>> pcap-file-number
  Success: 3

To display the list of queued files, do: ::
  
  >>> pcap-file-list
  Success: {'count': 2, 'files': ['/home/benches/file1.pcap', '/home/benches/file2.pcap']}

To display current processed file: ::
  
  >>> pcap-current
  Success:
  "/tmp/test.pcap"

When passing in a directory, you can see last processed time (modified time of last file) in milliseconds since epoch:

::

  >>> pcap-last-processed
  Success:
  1509138964000

To interrupt directory processing which terminates the current state:

::

  >>> pcap-interrupt
  Success:
  "Interrupted"

Build your own client
---------------------

The protocol is documented in the following page
https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Unix_Socket#Protocol

The following session show what is sent (SND) and received (RCV) by
the server. Initial negotiation is the following: ::
  
  # suricatasc
  SND: {"version": "0.1"}
  RCV: {"return": "OK"}

Once this is done, commands can be issued: ::
  
  >>> iface-list
  SND: {"command": "iface-list"}
  RCV: {"message": {"count": 1, "ifaces": ["wlan0"]}, "return": "OK"}
  Success: {'count': 1, 'ifaces': ['wlan0']}
  >>> iface-stat wlan0
  SND: {"command": "iface-stat", "arguments": {"iface": "wlan0"}}
  RCV: {"message": {"pkts": 41508, "drop": 0, "invalid-checksums": 0}, "return": "OK"}
  Success: {'pkts': 41508, 'drop': 0, 'invalid-checksums': 0}

In pcap-file mode, this gives: ::
  
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
  >>> pcap-file-continuous /home/eric/git/oisf/benches /tmp/bench 0 true
  SND: {"command": "pcap-file", "arguments": {"output-dir": "/tmp/bench", "filename": "/home/eric/git/oisf/benches/sandnet.pcap", "tenant": 0, "delete-when-done": true}}
  RCV: {"message": "Successfully added file to list", "return": "OK"}
  Success: Successfully added file to list

There is one thing to be careful about: a Suricata message is sent in
multiple send operations. This result in possible incomplete read on
client side. The worse workaround is to sleep a bit before trying a
recv call. An other solution is to use non blocking socket and retry a
recv if the previous one has failed.

Pcap-file json format is:

::

  {
    "command": "pcap-file",
    "arguments": {
      "output-dir": "path to output dir",
      "filename": "path to file or directory to run",
      "tenant": 0,
      "continuous": false,
      "delete-when-done": false
    }
  }

`output-dir` and `filename` are required. `tenant` is optional and should be a
number, indicating which tenant the file or directory should run under. `continuous`
is optional and should be true/false, indicating that file or directory should be
run until `pcap-interrupt` is sent or ctrl-c is invoked. `delete-when-done` is
optional and should be true/false, indicating that the file or files under the
directory specified by `filename` should be deleted when processing is complete.
`delete-when-done` defaults to false, indicating files will be kept after
processing.

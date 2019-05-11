.. Start with the most common basic commands.

.. option:: shutdown

   Shut Suricata instance down.

.. option:: command-list

   List available commands.

.. option:: help

   Get help about the available commands.

.. option:: version

   Print the version of Suricata instance.

.. option:: uptime

   Display the uptime of Suricata.

.. option:: running-mode

   Display running mode. This can either be *workers*, *autofp* or *single*.

.. option:: capture-mode

   Display the capture mode. This can be either of *PCAP_DEV*,
   *PCAP_FILE*, *PFRING(DISABLED)*, *NFQ*, *NFLOG*, *IPFW*, *ERF_FILE*,
   *ERF_DAG*, *AF_PACKET_DEV*, *NETMAP(DISABLED)*, *UNIX_SOCKET* or
   *WINDIVERT(DISABLED)*.

.. option:: conf-get <variable>

   Get configuration value for a given variable. Variable to be provided can be
   either of the configuration parameters that are written in suricata.yaml.

.. option:: dump-counters

   Dump Suricata's performance counters.

.. option:: ruleset-reload-rules

   Reload the ruleset and wait for completion.

.. option:: reload-rules

   Alias of option *ruleset-reload-rules*.

.. option:: ruleset-reload-nonblocking

   Reload ruleset and proceed without waiting.

.. option:: ruleset-reload-time

   Return time of last reload.

.. option:: ruleset-stats

   Display the number of rules loaded and failed.

.. option:: ruleset-failed-rules

   Display the list of failed rules.

.. option:: register-tenant-handler <id> <htype> [hargs]

   Register a tenant handler with the specified mapping.

.. option:: unregister-tenant-handler <id> <htype> [hargs]

   Unregister a tenant handler with the specified mapping.

.. option:: register-tenant <id> <filename>

   Register tenant with a particular ID and filename.

.. option:: reload-tenant <id> <filename>

   Reload a tenant with specified ID and filename.

.. option:: unregister-tenant <id>

   Unregister tenant with a particular ID.

.. option:: add-hostbit <ipaddress> <hostbit> <expire>

   Add hostbit on a host IP with a particular bit name and time of expiry.

.. option:: remove-hostbit <ipaddress> <hostbit>

   Remove hostbit on a host IP with specified IP address and bit name.

.. option:: list-hostbit <ipaddress>

   List hostbit for a particular host IP.

.. option:: reopen-log-files

   Reopen log files to be run after external log rotation.

.. option:: memcap-set <config> <memcap>

   Update memcap value of a specified item.

.. option:: memcap-show <config>

   Show memcap value of a specified item.

.. option:: memcap-list

   List all memcap values available.

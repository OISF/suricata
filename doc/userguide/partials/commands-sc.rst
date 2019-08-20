.. Consider converting `.. description` to `.. option` when the
   minimum version of Sphinx on the primary distributions are all
   updated to generate duplicate reference links. For example, we
   can't use `.. option` on CentOS 7 which has Sphinx 1.1.3, but
   Fedora 30 with Sphinx 1.8.4 is fine.

.. Start with the most common basic commands.

.. describe:: shutdown

   Shut Suricata instance down.

.. describe:: command-list

   List available commands.

.. describe:: help

   Get help about the available commands.

.. describe:: version

   Print the version of Suricata instance.

.. describe:: uptime

   Display the uptime of Suricata.

.. describe:: running-mode

   Display running mode. This can either be *workers*, *autofp* or *single*.

.. describe:: capture-mode

   Display the capture mode. This can be either of *PCAP_DEV*,
   *PCAP_FILE*, *PFRING(DISABLED)*, *NFQ*, *NFLOG*, *IPFW*, *ERF_FILE*,
   *ERF_DAG*, *AF_PACKET_DEV*, *NETMAP(DISABLED)*, *UNIX_SOCKET* or
   *WINDIVERT(DISABLED)*.

.. describe:: conf-get <variable>

   Get configuration value for a given variable. Variable to be provided can be
   either of the configuration parameters that are written in suricata.yaml.

.. describe:: dump-counters

   Dump Suricata's performance counters.

.. describe:: ruleset-reload-rules

   Reload the ruleset and wait for completion.

.. describe:: reload-rules

   Alias .. describe *ruleset-reload-rules*.

.. describe:: ruleset-reload-nonblocking

   Reload ruleset and proceed without waiting.

.. describe:: ruleset-reload-time

   Return time of last reload.

.. describe:: ruleset-stats

   Display the number of rules loaded and failed.

.. describe:: ruleset-failed-rules

   Display the list of failed rules.

.. describe:: register-tenant-handler <id> <htype> [hargs]

   Register a tenant handler with the specified mapping.

.. describe:: unregister-tenant-handler <id> <htype> [hargs]

   Unregister a tenant handler with the specified mapping.

.. describe:: register-tenant <id> <filename>

   Register tenant with a particular ID and filename.

.. describe:: reload-tenant <id> <filename>

   Reload a tenant with specified ID and filename.

.. describe:: unregister-tenant <id>

   Unregister tenant with a particular ID.

.. describe:: add-hostbit <ipaddress> <hostbit> <expire>

   Add hostbit on a host IP with a particular bit name and time of expiry.

.. describe:: remove-hostbit <ipaddress> <hostbit>

   Remove hostbit on a host IP with specified IP address and bit name.

.. describe:: list-hostbit <ipaddress>

   List hostbit for a particular host IP.

.. describe:: reopen-log-files

   Reopen log files to be run after external log rotation.

.. describe:: memcap-set <config> <memcap>

   Update memcap value of a specified item.

.. describe:: memcap-show <config>

   Show memcap value of a specified item.

.. describe:: memcap-list

   List all memcap values available.

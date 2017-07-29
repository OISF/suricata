Log Rotation
============

All outputs in the :ref:`outputs <suricata_yaml_outputs>` section of
the configuration file can be subject to log rotation.

For most outputs an external tool like *logrotate* is required to
rotate the log files in combination with sending a SIGHUP to Suricata
to notify it that the log files have been rotated.

On receipt of a SIGHUP, Suricata simply closes all open log files and
then re-opens them in append mode. If the external tool has renamed
any of the log files, new files will be created, otherwise the files
will be re-opened and new data will be appended to them with no
noticeable affect.

The following is an example *logrotate* configuration file that will
rotate Suricata log files then send Suricata a SIGHUP triggering
Suricata to open new files:

::

  /var/log/suricata/*.log /var/log/suricata/*.json
  {
      rotate 3
      missingok
      nocompress
      create
      sharedscripts
      postrotate
              /bin/kill -HUP `cat /var/run/suricata.pid 2>/dev/null` 2>/dev/null || true
      endscript
  }

.. note:: The above *logrotate* configuration file depends on the
          existence of a Suricata PID file. If running in daemon mode
          a PID file will be created by default, otherwise the
          :option:`--pidfile` option should be used to create a PID file.

In addition to the SIGHUP style rotation discussed above, some outputs
support their own time and date based rotation, however removal of old
log files is still the responsibility of external tools. These outputs
include:

- :ref:`Eve <output_eve_rotate>`
- :ref:`Unified2 <suricata_yaml_unified2>`
- :ref:`PCAP log <suricata_yaml_pcap_log>`

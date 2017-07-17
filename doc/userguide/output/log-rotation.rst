Log Rotation
============

Suricata can generate lot of output, so it's important to manage the files
to avoid issues with disks filling up.

A HUP signal sent to Suricata will force it to reopen the logfiles.

Example logrotate file:

::

  /var/log/suricata/*.log /var/log/suricata/*.json
  {
      rotate 3
      missingok
      nocompress
      create
      sharedscripts
      postrotate
              /bin/kill -HUP $(cat /var/run/suricata.pid)
      endscript
  }


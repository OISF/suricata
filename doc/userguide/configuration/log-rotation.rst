Log Rotation
============

Starting with Suricata version 2.0.2 (#1200), log rotation is made a
lot easier. A HUP signal sent to Suricata will force it to reopen the
logfiles.

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


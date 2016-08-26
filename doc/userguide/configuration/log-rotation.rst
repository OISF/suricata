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

newsyslog based log rotation (e.g. on OpenBSD) /etc/newsyslog.conf:
  
::
  
  /var/log/suricata/eve.json       root:wheel      640     1       *       24      B       /var/run/suricata.pid     SIGHUP

The above rotates every 24h; the 'B' prevents a rotation logmessage in
eve.json. Fieldseperator is a TAB.

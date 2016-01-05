.. _eve-json-output:

Eve JSON Output
===============

JSON output

Starting in 2.0, Suricata can output alerts, http events, dns events, tls events and file info through json.

The most common way to use this is through 'EVE', which is a firehose approach where all these logs go into a single file.

  
::

  
  outputs:
    - eve-log:
        enabled: yes
        type: file #file|syslog|unix_dgram|unix_stream
        filename: eve.json
        types:
          - alert
          - http:
              extended: yes     # enable this for extended logging information
          - dns
          - tls:
              extended: yes     # enable this for extended logging information
          - files:
              force-magic: no   # force logging magic on all logged files
              force-md5: no     # force logging of md5 checksums
          #- drop
          - ssh

Each alert, http log, etc will go into this one file: 'eve.json'. This file can than be processed by Logstash for example.


Multiple Logger Instances
~~~~~~~~~~~~~~~~~~~~~~~~~

It is possible to have multiple 'EVE' instances, for example the following is valid:
  
::

  
  outputs:
    - eve-log:
        enabled: yes
        type: file
        filename: eve-ips.json
        types:
          - alert
          - drop
  
    - eve-log:
        enabled: yes
        type: file
        filename: eve-nsm.json
        types:
          - http
          - dns
          - tls

So here the alerts and drops go into 'eve-ips.json', while http, dns and tls go into 'eve-nsm.json'.

In addition to this, each log can be handled completely separately:
  
::

  
  outputs:
    - alert-json-log:
        enabled: yes
        filename: alert-json.log
    - dns-json-log:
        enabled: yes
        filename: dns-json.log
    - drop-json-log:
        enabled: yes
        filename: drop-json.log
    - http-json-log:
        enabled: yes
        filename: http-json.log
    - ssh-json-log:
        enabled: yes
        filename: ssh-json.log
    - tls-json-log:
        enabled: yes
        filename: tls-json.log

For most output types, you can add multiple:
  
::

  
  outputs:
    - alert-json-log:
        enabled: yes
        filename: alert-json1.log
    - alert-json-log:
        enabled: yes
        filename: alert-json2.log

Except for drop and tls, for those only one logger instance is supported.

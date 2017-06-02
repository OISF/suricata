.. _eve-json-output:

Eve JSON Output
===============

Suricata can output alerts, http events, dns events, tls events and file info through json.

The most common way to use this is through 'EVE', which is a firehose approach where all these logs go into a single file.


::

  # Extensible Event Format (nicknamed EVE) event log in JSON format
  - eve-log:
      enabled: yes
      filetype: regular #regular|syslog|unix_dgram|unix_stream|redis
      filename: eve.json
      #prefix: "@cee: " # prefix to prepend to each log entry
      # the following are valid when type: syslog above
      #identity: "suricata"
      #facility: local5
      #level: Info ## possible levels: Emergency, Alert, Critical,
                   ## Error, Warning, Notice, Info, Debug
      #redis:
      #  server: 127.0.0.1
      #  port: 6379
      #  async: true ## if redis replies are read asynchronously
      #  mode: list ## possible values: list|lpush (default), rpush, channel|publish
      #             ## lpush and rpush are using a Redis list. "list" is an alias for lpush
      #             ## publish is using a Redis channel. "channel" is an alias for publish
      #  key: suricata ## key or channel to use (default to suricata)
      # Redis pipelining set up. This will enable to only do a query every
      # 'batch-size' events. This should lower the latency induced by network
      # connection at the cost of some memory. There is no flushing implemented
      # so this setting as to be reserved to high traffic suricata.
      #  pipelining:
      #    enabled: yes ## set enable to yes to enable query pipelining
      #    batch-size: 10 ## number of entry to keep in buffer
      types:
        - alert:
            # payload: yes             # enable dumping payload in Base64
            # payload-buffer-size: 4kb # max size of payload buffer to output in eve-log
            # payload-printable: yes   # enable dumping payload in printable (lossy) format
            # packet: yes              # enable dumping of packet (without stream segments)
            http: yes                # enable dumping of http fields
            tls: yes                 # enable dumping of tls fields
            ssh: yes                 # enable dumping of ssh fields
            smtp: yes                # enable dumping of smtp fields

            # Enable the logging of tagged packets for rules using the
            # "tag" keyword.
            tagged-packets: yes

            # HTTP X-Forwarded-For support by adding an extra field or overwriting
            # the source or destination IP address (depending on flow direction)
            # with the one reported in the X-Forwarded-For HTTP header. This is
            # helpful when reviewing alerts for traffic that is being reverse
            # or forward proxied.
            xff:
              enabled: no
              # Two operation modes are available, "extra-data" and "overwrite".
              mode: extra-data
              # Two proxy deployments are supported, "reverse" and "forward". In
              # a "reverse" deployment the IP address used is the last one, in a
              # "forward" deployment the first IP address is used.
              deployment: reverse
              # Header name where the actual IP address will be reported, if more
              # than one IP address is present, the last IP address will be the
              # one taken into consideration.
              header: X-Forwarded-For
        - http:
            extended: yes     # enable this for extended logging information
            # custom allows additional http fields to be included in eve-log
            # the example below adds three additional fields when uncommented
            #custom: [Accept-Encoding, Accept-Language, Authorization]
        - dns:
            # control logging of queries and answers
            # default yes, no to disable
            query: yes     # enable logging of DNS queries
            answer: yes    # enable logging of DNS answers
            # control which RR types are logged
            # all enabled if custom not specified
            #custom: [a, aaaa, cname, mx, ns, ptr, txt]
        - tls:
            extended: yes     # enable this for extended logging information
            # custom allows to control which tls fields that are included
            # in eve-log
            #custom: [subject, issuer, fingerprint, sni, version, not_before, not_after, certificate, chain]

        - files:
            force-magic: no   # force logging magic on all logged files
            # force logging of checksums, available hash functions are md5,
            # sha1 and sha256
            #force-hash: [md5]
        #- drop:
        #    alerts: yes      # log alerts that caused drops
        #    flows: all       # start or all: 'start' logs only a single drop
        #                     # per flow direction. All logs each dropped pkt.
        - smtp:
            #extended: yes # enable this for extended logging information
            # this includes: bcc, message-id, subject, x_mailer, user-agent
            # custom fields logging from the list:
            #  reply-to, bcc, message-id, subject, x-mailer, user-agent, received,
            #  x-originating-ip, in-reply-to, references, importance, priority,
            #  sensitivity, organization, content-md5, date
            #custom: [received, x-mailer, x-originating-ip, relays, reply-to, bcc]
            # output md5 of fields: body, subject
            # for the body you need to set app-layer.protocols.smtp.mime.body-md5
            # to yes
            #md5: [body, subject]

        - ssh
        - stats:
            totals: yes       # stats for all threads merged together
            threads: no       # per thread stats
            deltas: no        # include delta values
        # bi-directional flows
        - flow
        # uni-directional flows
        #- netflow

Each alert, http log, etc will go into this one file: 'eve.json'. This file
can then be processed by 3rd party tools like Logstash or jq.

Output types
~~~~~~~~~~~~

EVE can output to multiple methods. ``regular`` is a normal file. Other
options are ``syslog``, ``unix_dgram``, ``unix_stream`` and ``redis``.

Output types::

      filetype: regular #regular|syslog|unix_dgram|unix_stream|redis
      filename: eve.json
      #prefix: "@cee: " # prefix to prepend to each log entry
      # the following are valid when type: syslog above
      #identity: "suricata"
      #facility: local5
      #level: Info ## possible levels: Emergency, Alert, Critical,
                   ## Error, Warning, Notice, Info, Debug
      #redis:
      #  server: 127.0.0.1
      #  port: 6379
      #  async: true ## if redis replies are read asynchronously
      #  mode: list ## possible values: list|lpush (default), rpush, channel|publish
      #             ## lpush and rpush are using a Redis list. "list" is an alias for lpush
      #             ## publish is using a Redis channel. "channel" is an alias for publish
      #  key: suricata ## key or channel to use (default to suricata)
      # Redis pipelining set up. This will enable to only do a query every
      # 'batch-size' events. This should lower the latency induced by network
      # connection at the cost of some memory. There is no flushing implemented
      # so this setting as to be reserved to high traffic suricata.
      #  pipelining:
      #    enabled: yes ## set enable to yes to enable query pipelining
      #    batch-size: 10 ## number of entry to keep in buffer

Alerts
~~~~~~

Alerts are event records for rule matches. They can be ammended with metadata,
such as the HTTP record an alert was generated for.

Metadata::

        - alert:
            # payload: yes             # enable dumping payload in Base64
            # payload-buffer-size: 4kb # max size of payload buffer to output in eve-log
            # payload-printable: yes   # enable dumping payload in printable (lossy) format
            # packet: yes              # enable dumping of packet (without stream segments)
            # http-body: yes           # enable dumping of http body in Base64
            # http-body-printable: yes # enable dumping of http body in printable format
            metadata: yes              # add L7/applayer fields, flowbit and other vars to the alert

Alternatively to the `metadata` key it is also possible to select the application
layer metadata to output on a per application layer basis ::

        - alert:
            http: yes                # enable dumping of http fields
            tls: yes                 # enable dumping of tls fields
            ssh: yes                 # enable dumping of ssh fields
            smtp: yes                # enable dumping of smtp fields
            dnp3: yes                # enable dumping of dnp3 fields
            flow: yes                # enable dumping of a partial flow entry
            vars: yes                # enable dumping of flowbits and other vars

The `vars` will enable dumping of a set of key/value based on flowbits and other vars
such as named groups in regular expression.

DNS
~~~

DNS records are logged one log record per query/answer record.

YAML::

        - dns:
            # control logging of queries and answers
            # default yes, no to disable
            query: yes     # enable logging of DNS queries
            answer: yes    # enable logging of DNS answers
            # control which RR types are logged
            # all enabled if custom not specified
            #custom: [a, aaaa, cname, mx, ns, ptr, txt]

To reduce verbosity the output can be filtered by supplying the record types
to be logged under ``custom``.

TLS
~~~

TLS records are logged one record per session.

YAML::

        - tls:
            extended: yes     # enable this for extended logging information
            # custom allows to control which tls fields that are included
            # in eve-log
            #custom: [subject, issuer, serial, fingerprint, sni, version, not_before, not_after, certificate, chain]

The default is to log certificate subject and issuer. If ``extended`` is
enabled, then the log gets more verbose.

By using ``custom`` it is possible to select which TLS fields to log.

Date modifiers in filename
~~~~~~~~~~~~~~~~~~~~~~~~~~

It is possible to use date modifiers in the eve-log filename.

::

   outputs:
     - eve-log:
         filename: eve-%s.json

The example above adds epoch time to the filename. All the date modifiers from the
C library should be supported. See the man page for ``strftime`` for all supported
modifiers.

.. _output_eve_rotate:

Rotate log file
~~~~~~~~~~~~~~~

Eve-log can be configured to rotate based on time.

::

  outputs:
    - eve-log:
        filename: eve-%Y-%m-%d-%H:%M.json
        rotate-interval: minute

The example above creates a new log file each minute, where the filename contains
a timestamp. Other supported ``rotate-interval`` values are ``hour`` and ``day``.

In addition to this, it is also possible to specify the ``rotate-interval`` as a
relative value. One example is to rotate the log file each X seconds.

::

  outputs:
    - eve-log:
        filename: eve-%Y-%m-%d-%H:%M:%S.json
        rotate-interval: 30s

The example above rotates eve-log each 30 seconds. This could be replaced with
``30m`` to rotate every 30 minutes, ``30h`` to rotate every 30 hours, ``30d``
to rotate every 30 days, or ``30w`` to rotate every 30 weeks.

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

Except for ``drop`` for which only a single logger instance is supported.

File permissions
~~~~~~~~~~~~~~~~

Log file permissions can be set individually for each logger. ``filemode`` can be used to
control the permissions of a log file, e.g.:

::

  outputs:
    - eve-log:
        enabled: yes
        filename: eve.json
        filemode: 600

The example above sets the file permissions on ``eve.json`` to 600, which means that it is
only readable and writable by the owner of the file.

JSON flags
~~~~~~~~~~

Several flags can be specified to control the JSON output in EVE:

::

  outputs:
    - eve-log:
        json:
          # Sort object keys in the same order as they were inserted
          preserve-order: yes

          # Make the output more compact
          compact: yes

          # Escape all unicode characters outside the ASCII range
          ensure-ascii: yes

          # Escape the '/' characters in string with '\/'
          escape-slash: yes

All these flags are enabled by default, and can be modified per EVE instance.

.. _eve-json-output:

Eve JSON Output
===============

The EVE output facility outputs alerts, anomalies, metadata, file info and protocol
specific records through JSON.

The most common way to use this is through 'EVE', which is a firehose approach
where all these logs go into a single file.

.. literalinclude:: ../../partials/eve-log.yaml

Each alert, http log, etc will go into this one file: 'eve.json'. This file
can then be processed by 3rd party tools like Logstash (ELK) or jq.

If ``ethernet`` is set to yes, then ethernet headers will be added to events
if available.

Output types
~~~~~~~~~~~~

EVE can output to multiple methods. ``regular`` is a normal file. Other
options are ``syslog``, ``unix_dgram``, ``unix_stream`` and ``redis``.

Output types::

      filetype: regular #regular|syslog|unix_dgram|unix_stream|redis
      filename: eve.json
      # Enable for multi-threaded eve.json output; output files are amended
      # with an identifier, e.g., eve.9.json. Default: off
      #threaded: off
      #prefix: "@cee: " # prefix to prepend to each log entry
      # the following are valid when type: syslog above
      #identity: "suricata"
      #facility: local5
      #level: Info ## possible levels: Emergency, Alert, Critical,
                   ## Error, Warning, Notice, Info, Debug
      #ethernet: no # log ethernet header in events when available
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

Alerts are event records for rule matches. They can be amended with
metadata, such as the application layer record (HTTP, DNS, etc) an
alert was generated for, and elements of the rule.

Metadata::

        - alert:
            #payload: yes             # enable dumping payload in Base64
            #payload-buffer-size: 4kb # max size of payload buffer to output in eve-log
            #payload-printable: yes   # enable dumping payload in printable (lossy) format
            #packet: yes              # enable dumping of packet (without stream segments)
            #http-body: yes           # Requires metadata; enable dumping of http body in Base64
            #http-body-printable: yes # Requires metadata; enable dumping of http body in printable format

            # metadata:

              # Include the decoded application layer (ie. http, dns)
              #app-layer: true

              # Log the the current state of the flow record.
              #flow: true

              #rule:
                # Log the metadata field from the rule in a structured
                # format.
                #metadata: true

                # Log the raw rule text.
                #raw: false

Anomaly
~~~~~~~

Anomalies are event records created when packets with unexpected or anomalous
values are handled. These events include conditions such as incorrect protocol
values, incorrect protocol length values, and other conditions which render the
packet suspect. Other conditions may occur during the normal progression of a stream;
these are termed ``stream`` events are include control sequences with incorrect
values or that occur out of expected sequence.

Anomalies are reported by and configured by type:

- Decode
- Stream
- Application layer

Metadata::

    - anomaly:
        # Anomaly log records describe unexpected conditions such as truncated packets,
        # packets with invalid IP/UDP/TCP length values, and other events that render
        # the packet invalid for further processing or describe unexpected behavior on
        # an established stream. Networks which experience high occurrences of
        # anomalies may experience packet processing degradation.
        #
        # Anomalies are reported for the following:
        # 1. Decode: Values and conditions that are detected while decoding individual
        #    packets. This includes invalid or unexpected values for low-level protocol
        #    lengths as well.
        # 2. Stream: This includes stream related events (TCP 3-way handshake issues,
        #    unexpected sequence number, etc).
        # 3. Application layer: These denote application layer specific conditions that
        #    are unexpected, invalid or are unexpected given the application monitoring
        #    state.
        #
        # By default, anomaly logging is disabled. When anomaly logging is enabled,
        # application-layer anomaly reporting is enabled.
        #
        # Choose one or both types of anomaly logging and whether to enable
        # logging of the packet header for packet anomalies.
        types:
          #decode: no
          #stream: no
          #applayer: yes
        #packethdr: no

HTTP
~~~~

HTTP transaction logging.

Config::

    - http:
        extended: yes     # enable this for extended logging information
        # custom allows additional http fields to be included in eve-log
        # the example below adds three additional fields when uncommented
        #custom: [Accept-Encoding, Accept-Language, Authorization]
        # set this value to one among {both, request, response} to dump all
        # http headers for every http request and/or response
        # dump-all-headers: [both, request, response]

List of custom fields:

======================  ======================
Yaml Option             HTTP Header
======================  ======================
accept                  accept
accept_charset          accept-charset
accept_encoding         accept-encoding
accept_language         accept-language
accept_datetime         accept-datetime
authorization           authorization
cache_control           cache-control
cookie                  cookie
from                    from
max_forwards            max-forwards
origin                  origin
pragma                  pragma
proxy_authorization     proxy-authorization
range                   range
te                      te
via                     via
x_requested_with        x-requested-with
dnt                     dnt
x_forwarded_proto       x-forwarded-proto
x_authenticated_user    x-authenticated-user
x_flash_version         x-flash-version
accept_range            accept-range
age                     age
allow                   allow
connection              connection
content_encoding        content-encoding
content_language        content-language
content_length          content-length
content_location        content-location
content_md5             content-md5
content_range           content-range
content_type            content-type
date                    date
etag                    etags
expires                 expires
last_modified           last-modified
link                    link
location                location
proxy_authenticate      proxy-authenticate
referrer                referrer
refresh                 refresh
retry_after             retry-after
server                  server
set_cookie              set-cookie
trailer                 trailer
transfer_encoding       transfer-encoding
upgrade                 upgrade
vary                    vary
warning                 warning
www_authenticate        www-authenticate
true_client_ip          true-client-ip
org_src_ip              org-src-ip
x_bluecoat_via          x-bluecoat-via
======================  ======================

In the ``custom`` option values from both columns can be used. The
``HTTP Header`` column is case insensitive.

.. _output-eve-dns:

DNS
~~~

.. note:: As of Suricata 7.0 the v1 EVE DNS format has been removed.

DNS records are logged as one entry for the request, and one entry for
the response.

YAML::

        - dns:
            #version: 2

            # Enable/disable this logger. Default: enabled.
            #enabled: yes

            # Control logging of requests and responses:
            # - requests: enable logging of DNS queries
            # - responses: enable logging of DNS answers
            # By default both requests and responses are logged.
            #requests: no
            #responses: no

            # Format of answer logging:
            # - detailed: array item per answer
            # - grouped: answers aggregated by type
            # Default: all
            #formats: [detailed, grouped]

            # Types to log, based on the query type.
            # Default: all.
            #types: [a, aaaa, cname, mx, ns, ptr, txt]

TLS
~~~

TLS records are logged one record per session.

YAML::

        - tls:
            extended: yes     # enable this for extended logging information
            # custom allows to control which tls fields that are included
            # in eve-log
            #custom: [subject, issuer, serial, fingerprint, sni, version, not_before, not_after, certificate, chain, ja3, ja3s]

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

Threaded file output
~~~~~~~~~~~~~~~~~~~~

By default, all output is written to the named filename in the outputs section. The ``threaded`` option enables
each output thread to write to individual files. In this case, the ``filename`` will include a unique identifier.

With ``threaded`` enabled, the output will be split among many files -- and
the aggregate of each file's contents must be treated together.

::

   outputs:
     - eve-log:
         filename: eve.json
         threaded: on

This example will cause each Suricata thread to write to its own "eve.json" file. Filenames are constructed
by adding a unique identifier to the filename.  For example, ``eve.7.json``.


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

.. _multiple-eve-instances:

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

With the exception of ``drop``, you can specify multiples of the same
logger type, however, ``drop`` can only be used once.

.. note:: The use of independent json loggers such as alert-json-log,
          dns-json-log, etc. has been deprecated and will be removed
          by June 2020. Please use multiple eve-log instances as
          documented above instead. Please see the `deprecation
          policy`_ for more information.

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

Community Flow ID
~~~~~~~~~~~~~~~~~

Often Suricata is used in combination with other tools like Bro/Zeek. Enabling
the community-id option in the eve-log section adds a new ``community_id``
field to each output.

Example::

    {
      "timestamp": "2003-12-16T13:21:44.891921+0000",
      "flow_id": 1332028388187153,
      "pcap_cnt": 1,
      "event_type": "alert",
      ...
      "community_id": "1:LQU9qZlK+B5F3KDmev6m5PMibrg=",
      "alert": {
        "action": "allowed",
        "gid": 1,
        "signature_id": 1,
      },
    }
    {
      "timestamp": "2003-12-16T13:21:45.037333+0000",
      "flow_id": 1332028388187153,
      "event_type": "flow",
      "flow": {
        "pkts_toserver": 5,
        "pkts_toclient": 4,
        "bytes_toserver": 338,
        "bytes_toclient": 272,
        "start": "2003-12-16T13:21:44.891921+0000",
        "end": "2003-12-16T13:21:45.346457+0000",
        "age": 1,
        "state": "closed",
        "reason": "shutdown",
        "alerted": true
      },
      "community_id": "1:LQU9qZlK+B5F3KDmev6m5PMibrg=",
    }

Options
"""""""

The output can be enabled per instance of the EVE logger.

The ``community-id`` option is boolean. If set to ``true`` it is enabled.
The ``community-id-seed`` option specifies a unsigned 16 bit value that
is used a seed to the hash that is calculated for the ``community-id``
output. This must be set to the same value on all tools that output this
record.
The ``encrypted-traffic-metadata`` option is boolean. If set to ``true`` it 
is enabled. If this option is enabled it will output additonal fields that
can be used for encrypted traffic analysis. Encrypted traffic analysis is a
type of side-channel analysis and threat detection that can be performed on
encrypted network connections while maintaining the privacy and network
integrity provided by a fully encrypted system.

YAML::

  - eve-log:
      # Community Flow ID
      # Adds a 'community_id' field to EVE records. These are meant to give
      # a records a predictable flow id that can be used to match records to
      # output of other tools such as Bro.
      #
      # Takes a 'seed' that needs to be same across sensors and tools
      # to make the id less predictable.

      # enable/disable the community id feature.
      community-id: false
      # Seed value for the ID output. Valid values are 0-65535.
      community-id-seed: 0
      # enable/disable encrypted traffic metadata feature.
      encrypted-traffic-metadata: false

Multi Tenancy
-------------

Suricata can be configured to support multiple tenants with different detection
engine configurations. When these tenants are configured and the detection
engine is running then all EVE logging will also report the ``tenant_id`` field
for traffic matching a specific tenant.

.. _deprecation policy: https://suricata-ids.org/about/deprecation-policy/

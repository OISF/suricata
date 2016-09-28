.. _eve-json-format:

Eve JSON Format
===============

Example:

::


  {
      "timestamp": "2009-11-24T21:27:09.534255",
      "event_type": "alert",
      "src_ip": "192.168.2.7",
      "src_port": 1041,
      "dest_ip": "x.x.250.50",
      "dest_port": 80,
      "proto": "TCP",
      "alert": {
          "action": "allowed",
          "gid": 1,
          "signature_id" :2001999,
          "rev": 9,
          "signature": "ET MALWARE BTGrab.com Spyware Downloading Ads",
          "category": "A Network Trojan was detected",
          "severity": 1
      }
  }

Common Section
--------------

All the JSON log types share a common structure:

::


  {"timestamp":"2009-11-24T21:27:09.534255","event_type":"TYPE", ...tuple... ,"TYPE":{ ... type specific content ... }}

Event types
~~~~~~~~~~~

The common part has a field "event_type" to indicate the log type.

::


  "event_type":"TYPE"

Event type: Alert
-----------------

Field action
~~~~~~~~~~~~

Possible values: "allowed" and "blocked"

Example:

::


  "action":"allowed"

Action is set to "allowed" unless a rule used the "drop" action and Suricata is in IPS mode, or when the rule used the "reject" action.

Event type: HTTP
----------------

Fields
~~~~~~

* "hostname": The hostname this HTTP event is attributed to
* "url": URL at the hostname that was accessed
* "http_user_agent": The user-agent of the software that was used
* "http_content_type": The type of data returned (ex: application/x-gzip)
* "cookie"

In addition to these fields, if the extended logging is enabled in the suricata.yaml file the following fields are (can) also included:

* "length": The content size of the HTTP body
* "status": HTTP statuscode
* "protocol": Protocol / Version of HTTP (ex: HTTP/1.1)
* "http_method": The HTTP method (ex: GET, POST, HEAD)
* "http_refer": The referer for this action

In addition to the extended logging fields one can also choose to enable/add from 47 additional custom logging HTTP fields enabled in the suricata.yaml file. The additional fields can be enabled as following:


::


    - eve-log:
        enabled: yes
        type: file #file|syslog|unix_dgram|unix_stream
        filename: eve.json
        # the following are valid when type: syslog above
        #identity: "suricata"
        #facility: local5
        #level: Info ## possible levels: Emergency, Alert, Critical,
                     ## Error, Warning, Notice, Info, Debug
        types:
          - alert
          - http:
              extended: yes     # enable this for extended logging information
              # custom allows additional http fields to be included in eve-log
              # the example below adds three additional fields when uncommented
              #custom: [Accept-Encoding, Accept-Language, Authorization]
              custom: [accept, accept-charset, accept-encoding, accept-language,
              accept-datetime, authorization, cache-control, cookie, from,
              max-forwards, origin, pragma, proxy-authorization, range, te, via,
              x-requested-with, dnt, x-forwarded-proto, accept-range, age,
              allow, connection, content-encoding, content-language,
              content-length, content-location, content-md5, content-range,
              content-type, date, etags, last-modified, link, location,
              proxy-authenticate, referrer, refresh, retry-after, server,
              set-cookie, trailer, transfer-encoding, upgrade, vary, warning,
              www-authenticate, x-flash-version, x-authenticated-user]


The benefits here of using the extended logging is to see if this action for example was a POST or perhaps if a download of an executable actually returned any bytes.

Examples
~~~~~~~~

Event with non-extended logging:

::


  "http": {
      "hostname": "www.digip.org",
      "url" :"\/jansson\/releases\/jansson-2.6.tar.gz",
      "http_user_agent": "<User-Agent>",
      "http_content_type": "application\/x-gzip"
  }

Event with extended logging:

::


  "http": {
      "hostname": "direkte.vg.no",
      "url":".....",
      "http_user_agent": "<User-Agent>",
      "http_content_type": "application\/json",
      "http_refer": "http:\/\/www.vg.no\/",
      "http_method": "GET",
      "protocol": "HTTP\/1.1",
      "status":"200",
      "length":310
  }

Event type: DNS
---------------

Fields
~~~~~~

Outline of fields seen in the different kinds of DNS events:

* "type": Indicating DNS message type, can be "answer" or "query".
* "id": <needs explanation>
* "rrname": Resource Record Name (ex: a domain name)
* "rrtype": Resource Record Type (ex: A, AAAA, NS, PTR)
* "rdata": Resource Data (ex. IP that domain name resolves to)
* "ttl": Time-To-Live for this resource record


Examples
~~~~~~~~

Example of a DNS query for the IPv4 address of "twitter.com" (resource record type 'A'):

::


  "dns": {
      "type": "query",
      "id": 16000,
      "rrname": "twitter.com",
      "rrtype":"A"
  }

Example of a DNS answer with an IPv4 (resource record type 'A') return:

::


  "dns": {
      "type": "answer",
      "id":16000,
      "rrname": "twitter.com",
      "rrtype":"A",
      "ttl":8,
      "rdata": "199.16.156.6"
  }

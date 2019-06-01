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

PCAP fields
~~~~~~~~~~~

If Suricata is processing a pcap file, additional fields are added:

::

    "pcap_cnt": 123

``pcap_cnt`` contains the packet number in the pcap. This can be used to look
up a packet in Wireshark for example.

::

    "pcap_filename":"/path/to/file.pcap"

``pcap_filename`` contains the file name and location of the pcap that
generated the event.

.. note:: the pcap fields are only available on "real" packets, and are
          omitted from internal "pseudo" packets such as flow timeout
          packets.

Event type: Alert
-----------------

Field action
~~~~~~~~~~~~

Possible values: "allowed" and "blocked"

Example:

::


  "action":"allowed"

Action is set to "allowed" unless a rule used the "drop" action and Suricata is in IPS mode, or when the rule used the "reject" action.

It can also contain information about Source and Target of the attack in the alert.source and alert.target field it target keyword is used in
the signature.

::

   "alert": {
     "action": "allowed",
     "gid": 1,
     "signature_id": 1,
     "rev": 1,
     "app_proto": "http",
     "signature": "HTTP body talking about corruption",
     "severity": 3,
     "source": {
       "ip": "192.168.43.32",
       "port": 36292
     },
     "target": {
       "ip": "179.60.192.3",
       "port": 80
     },

Event type: Anomaly
-------------------

Events with type "anomaly" report unexpected conditions such as truncated packets, packets
with invalid values, events that render the packet invalid for further processing or unexpected
behaviors.

Networks which experience high occurrences of anomalies may experience packet processing degradation
when anomaly logging is enabled.

Fields
------

* "type": Either "packet", "stream" or "applayer". In rare cases, type will be "unknown".
  When this occurs, an additional field named "code" will be present. Events with type
  "applayer" are detected by the application layer parsers.
* "event" The name of the anomalous event. Events of type "packet" are prefixed
  with "decoder"; events of type "stream" are prefixed with "stream".
* "code" If "type" is "unknown", than "code" contains the unrecognized event code. Otherwise,
  this field is not present.

The following fields are included when "type" has the value "applayer":

* "layer"  Indicates the handling layer that detected the event. This will be "proto_parser"
  (protocol parser), "proto_detect" (protocol detection) or "parser."
* "event_no" This is an informational only field indicating the total number of events
  detected and the ordinal number of the event being reported. It is presented as "N (of M)"
  where "N" is the ordinal number of the event and "M" is the total number of events detected.

When ``packethdr`` is enabled, the first 32 bytes of the packet are included as a byte64-encoded blob in the main part of
record. This applies to events of "type" "packet" or "stream" only.

Examples
--------

::

	"anomaly": {
	  "type": "packet",
	  "event": "decoder.udp.pkt_too_small"
	}

	{
	  "timestamp": "2016-01-17T13:26:30.841742-0800",
	  "flow_id": 1848021463489450,
	  "pcap_cnt": 1393890,
	  "event_type": "anomaly",
	  "src_ip": "192.168.81.128",
	  "src_port": 50105,
	  "dest_ip": "31.148.99.125",
	  "dest_port": 80,
	  "proto": "TCP",
	  "anomaly": {
		"type": "stream",
		"event": "stream.reassembly_seq_gap"
	  }
	}

	{
	  "timestamp": "1969-12-31T16:04:21.000000-0800",
	  "pcap_cnt": 9262,
	  "event_type": "anomaly",
	  "src_ip": "208.21.2.184",
	  "src_port": 0,
	  "dest_ip": "10.1.1.99",
	  "dest_port": 0,
	  "proto": "UDP",
	  "packet": "////////AQEBAQEBCABFAAA8xZ5AAP8R1+DQFQK4CgE=",
	  "packet_info": {
		"linktype": 1
	  },
	  "anomaly": {
		"type": "packet",
		"event": "decoder.udp.pkt_too_small"
	  }
	}

	{
	  "timestamp": "2016-01-11T05:10:54.612110-0800",
	  "flow_id": 412547343494194,
	  "pcap_cnt": 1391293,
	  "event_type": "anomaly",
	  "src_ip": "192.168.122.149",
	  "src_port": 49324,
	  "dest_ip": "69.195.71.174",
	  "dest_port": 443,
	  "proto": "TCP",
	  "app_proto": "tls",
	  "anomaly": {
		"type": "applayer",
		"event": "APPLAYER_DETECT_PROTOCOL_ONLY_ONE_DIRECTION",
		"event_no": "1 (of 1)",
		"layer": "proto_detect"
	  }
	}

	{
	  "timestamp": "2016-01-11T05:10:52.828802-0800",
	  "flow_id": 201217772575257,
	  "pcap_cnt": 1391281,
	  "event_type": "anomaly",
	  "src_ip": "192.168.122.149",
	  "src_port": 49323,
	  "dest_ip": "69.195.71.174",
	  "dest_port": 443,
	  "proto": "TCP",
	  "tx_id": 0,
	  "app_proto": "tls",
	  "anomaly": {
		"type": "applayer",
		"event": "INVALID_RECORD_TYPE",
		"event_no": "1 (of 3)",
		"layer": "proto_parser"
	  }
	}

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
* "status": HTTP status code
* "protocol": Protocol / Version of HTTP (ex: HTTP/1.1)
* "http_method": The HTTP method (ex: GET, POST, HEAD)
* "http_refer": The referrer for this action

In addition to the extended logging fields one can also choose to enable/add from more than 50 additional custom logging HTTP fields enabled in the suricata.yaml file. The additional fields can be enabled as following:


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
              content-type, date, etags, expires, last-modified, link, location,
              proxy-authenticate, referrer, refresh, retry-after, server,
              set-cookie, trailer, transfer-encoding, upgrade, vary, warning,
              www-authenticate, x-flash-version, x-authenticated-user]


The benefits here of using the extended logging is to see if this action for example was a POST or perhaps if a download of an executable actually returned any bytes.

It is also possible to dump every header for HTTP requests/responses or both via the keyword ``dump-all-headers``.



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

In case the hostname shows a port number, such as in case there is a header "Host: www.test.org:1337":

::


  "http": {
      "http_port": 1337,
      "hostname": "www.test.org",
      "url" :"\/this\/is\/test.tar.gz",
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

Event with ``dump-all-headers`` set to "both":

::

  "http": {
      "hostname": "test.co.uk",
      "url":"\/test\/file.json",
      "http_user_agent": "<User-Agent>",
      "http_content_type": "application\/json",
      "http_refer": "http:\/\/www.test.com\/",
      "http_method": "GET",
      "protocol": "HTTP\/1.1",
      "status":"200",
      "length":310,
      "request_headers": [
          {
              "name": "User-Agent",
              "value": "Wget/1.13.4 (linux-gnu)"
          },
          {
              "name": "Accept",
              "value": "*/*"
          },
      ],
      "response_headers": [
          {
              "name": "Date",
              "value": "Wed, 25 Mar 2015 15:40:41 GMT"
          },
      ]
  }


Event type: DNS
---------------

A new version of dns logging has been introduced to improve how dns answers
are logged.

With that new version, dns answers are logged in one event
rather than an event for each answer.

It's possible to customize how a dns answer will be logged with the following
formats:

* "detailed": "rrname", "rrtype", "rdata" and "ttl" fields are logged for each answer
* "grouped": answers logged are aggregated by their type (A, AAAA, NS, ...)

It will be still possible to use the old DNS logging format, you can control it
with "version" option in dns configuration section.

Fields
~~~~~~

Outline of fields seen in the different kinds of DNS events:

* "type": Indicating DNS message type, can be "answer" or "query".
* "id": Identifier field
* "version": Indicating DNS logging version in use
* "flags": Indicating DNS answer flag, in hexadecimal (ex: 8180 , please note 0x is not output)
* "qr": Indicating in case of DNS answer flag, Query/Response flag (ex: true if set)
* "aa": Indicating in case of DNS answer flag, Authoritative Answer flag (ex: true if set)
* "tc": Indicating in case of DNS answer flag, Truncation flag (ex: true if set)
* "rd": Indicating in case of DNS answer flag, Recursion Desired flag (ex: true if set)
* "ra": Indicating in case of DNS answer flag, Recursion Available flag (ex: true if set)
* "rcode": (ex: NOERROR)
* "rrname": Resource Record Name (ex: a domain name)
* "rrtype": Resource Record Type (ex: A, AAAA, NS, PTR)
* "rdata": Resource Data (ex. IP that domain name resolves to)
* "ttl": Time-To-Live for this resource record


One can also control which RR types are logged explicitly from additional custom field enabled in the suricata.yaml file. If custom field is not specified, all RR types are logged. More than 50 values can be specified with the custom field and can be used as following:


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
          - dns:
            # control logging of queries and answers
            # default yes, no to disable
            query: yes     # enable logging of DNS queries
            answer: yes    # enable logging of DNS answers
            # control which RR types are logged
            # all enabled if custom not specified
            #custom: [a, aaaa, cname, mx, ns, ptr, txt]
            custom: [a, ns, md, mf, cname, soa, mb, mg, mr, null,
            wks, ptr, hinfo, minfo, mx, txt, rp, afsdb, x25, isdn,
            rt, nsap, nsapptr, sig, key, px, gpos, aaaa, loc, nxt,
            srv, atma, naptr, kx, cert, a6, dname, opt, apl, ds,
            sshfp, ipseckey, rrsig, nsec, dnskey, dhcid, nsec3,
            nsec3param, tlsa, hip, cds, cdnskey, spf, tkey,
            tsig, maila, any, uri]


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

Example of a DNS answer with "detailed" format:

::


  "dns": {
      "version": 2,
      "type": "answer",
      "id": 45444,
      "flags": "8180",
      "qr": true,
      "rd": true,
      "ra": true,
      "rcode": "NOERROR",
      "answers": [
        {
          "rrname": "www.suricata-ids.org",
          "rrtype": "CNAME",
          "ttl": 3324,
          "rdata": "suricata-ids.org"
        },
        {
          "rrname": "suricata-ids.org",
          "rrtype": "A",
          "ttl": 10,
          "rdata": "192.0.78.24"
        },
        {
          "rrname": "suricata-ids.org",
          "rrtype": "A",
          "ttl": 10,
          "rdata": "192.0.78.25"
        }
      ]
  }

Example of a DNS answer with "grouped" format:

::

  "dns": {
      "version": 2,
      "type": "answer",
      "id": 18523,
      "flags": "8180",
      "qr": true,
      "rd": true,
      "ra": true,
      "rcode": "NOERROR",
      "grouped": {
        "A": [
          "192.0.78.24",
          "192.0.78.25"
        ],
        "CNAME": [
          "suricata-ids.org"
        ]
      }
  }


Example of a old DNS answer with an IPv4 (resource record type 'A') return:

::


  "dns": {
      "type": "answer",
      "id":16000,
      "flags":"8180",
      "qr":true,
      "rd":true,
      "ra":true,
      "rcode":"NOERROR"
      "rrname": "twitter.com",
      "rrtype":"A",
      "ttl":8,
      "rdata": "199.16.156.6"
  }

Event type: TLS
---------------

Fields
~~~~~~

* "subject": The subject field from the TLS certificate
* "issuer": The issuer field from the TLS certificate
* "session_resumed": This field has the value of "true" if the TLS session was resumed via a session id. If this field appears, "subject" and "issuer" do not appear, since a TLS certificate is not seen.

If extended logging is enabled the following fields are also included:

* "serial": The serial number of the TLS certificate
* "fingerprint": The (SHA1) fingerprint of the TLS certificate
* "sni": The Server Name Indication (SNI) extension sent by the client
* "version": The SSL/TLS version used
* "not_before": The NotBefore field from the TLS certificate
* "not_after": The NotAfter field from the TLS certificate
* "ja3": The JA3 fingerprint consisting of both a JA3 hash and a JA3 string
* "ja3s": The JA3S fingerprint consisting of both a JA3 hash and a JA3 string

JA3 must be enabled in the Suricata config file (set 'app-layer.protocols.tls.ja3-fingerprints' to 'yes').

In addition to this, custom logging also allows the following fields:

* "certificate": The TLS certificate base64 encoded
* "chain": The entire TLS certificate chain base64 encoded

Examples
~~~~~~~~

Example of regular TLS logging:

::

  "tls": {
      "subject": "C=US, ST=California, L=Mountain View, O=Google Inc, CN=*.google.com",
      "issuerdn": "C=US, O=Google Inc, CN=Google Internet Authority G2"
  }

Example of regular TLS logging for resumed sessions:

::

  "tls": {
      "session_resumed": true
  }

Example of extended TLS logging:

::

  "tls": {
      "subject": "C=US, ST=California, L=Mountain View, O=Google Inc, CN=*.google.com",
      "issuerdn": "C=US, O=Google Inc, CN=Google Internet Authority G2",
      "serial": "0C:00:99:B7:D7:54:C9:F6:77:26:31:7E:BA:EA:7C:1C",
      "fingerprint": "8f:51:12:06:a0:cc:4e:cd:e8:a3:8b:38:f8:87:59:e5:af:95:ca:cd",
      "sni": "calendar.google.com",
      "version": "TLS 1.2",
      "notbefore": "2017-01-04T10:48:43",
      "notafter": "2017-03-29T10:18:00"
  }

Example of certificate logging using TLS custom logging (subject, sni, certificate):

::

  "tls": {
      "subject": "C=US, ST=California, L=Mountain View, O=Google Inc, CN=*.googleapis.com
      "sni": "www.googleapis.com",
      "certificate": "MIIE3TCCA8WgAwIBAgIIQPsvobRZN0gwDQYJKoZIhvcNAQELBQAwSTELMA [...]"
   }

Event type: TFTP
----------------

Fields
~~~~~~

* "packet": The operation code, can be "read" or "write" or "error"
* "file": The filename transported with the tftp protocol
* "mode": The mode field, can be "octet" or "mail" or "netascii" (or any combination of upper and lower case)

Example of TFTP logging:

::

  "tftp": {
      "packet": "write",
      "file": "rfc1350.txt",
      "mode": "octet"
   }


Event type: SMB
---------------

SMB Fields
~~~~~~~~~~

* "id" (integer): internal transaction id
* "dialect" (string): the negotiated protocol dialect, or "unknown" if missing
* "command" (string): command name. E.g. SMB2_COMMAND_CREATE or SMB1_COMMAND_WRITE_ANDX
* "status" (string): status string. Can be both NT_STATUS or DOS_ERR and other variants
* "status_code" (string): status code as hex string
* "session_id" (integer): SMB2+ session_id. SMB1 user id.
* "tree_id" (integer): Tree ID
* "filename" (string): filename for CREATE and other commands.
* "disposition" (string): requested disposition. E.g. FILE_OPEN, FILE_CREATE and FILE_OVERWRITE. See https://msdn.microsoft.com/en-us/library/ee442175.aspx#Appendix_A_Target_119
* "access" (string): indication of how the file was opened. "normal" or "delete on close" (field is subject to change)
* "created", "accessed", "modified", "changed" (integer): timestamps in seconds since unix epoch
* "size" (integer): size of the requested file
* "fuid" (string): SMB2+ file GUID. SMB1 FID as hex.
* "share" (string): share name.
* "share_type" (string): FILE, PIPE, PRINT or unknown.
* "client_dialects" (array of strings): list of SMB dialects the client speaks.
* "client_guid" (string): client GUID
* "server_guid" (string): server GUID
* "request.native_os" (string): SMB1 native OS string
* "request.native_lm" (string): SMB1 native Lan Manager string
* "response.native_os" (string): SMB1 native OS string
* "response.native_lm" (string): SMB1 native Lan Manager string

Examples of SMB logging:

Pipe open::

    "smb": {
      "id": 1,
      "dialect": "unknown",
      "command": "SMB2_COMMAND_CREATE",
      "status": "STATUS_SUCCESS",
      "status_code": "0x0",
      "session_id": 4398046511201,
      "tree_id": 1,
      "filename": "atsvc",
      "disposition": "FILE_OPEN",
      "access": "normal",
      "created": 0,
      "accessed": 0,
      "modified": 0,
      "changed": 0,
      "size": 0,
      "fuid": "0000004d-0000-0000-0005-0000ffffffff"
    }

File/pipe close::

  "smb": {
    "id": 15,
    "dialect": "2.10",
    "command": "SMB2_COMMAND_CLOSE",
    "status": "STATUS_SUCCESS",
    "status_code": "0x0",
    "session_id": 4398046511121,
    "tree_id": 1,
  }

Tree connect (share open)::

  "smb": {
    "id": 3,
    "dialect": "2.10",
    "command": "SMB2_COMMAND_TREE_CONNECT",
    "status": "STATUS_SUCCESS",
    "status_code": "0x0",
    "session_id": 4398046511121,
    "tree_id": 1,
    "share": "\\\\admin-pc\\c$",
    "share_type": "FILE"
  }

Dialect negotiation from SMB1 to SMB2 dialect 2.10::

  "smb": {
    "id": 1,
    "dialect": "2.??",
    "command": "SMB1_COMMAND_NEGOTIATE_PROTOCOL",
    "status": "STATUS_SUCCESS",
    "status_code": "0x0",
    "session_id": 0,
    "tree_id": 0,
    "client_dialects": [
      "PC NETWORK PROGRAM 1.0",
      "LANMAN1.0",
      "Windows for Workgroups 3.1a",
      "LM1.2X002",
      "LANMAN2.1",
      "NT LM 0.12",
      "SMB 2.002",
      "SMB 2.???"
    ],
    "server_guid": "aec6e793-2b11-4019-2d95-55453a0ad2f1"
  }
  "smb": {
    "id": 2,
    "dialect": "2.10",
    "command": "SMB2_COMMAND_NEGOTIATE_PROTOCOL",
    "status": "STATUS_SUCCESS",
    "status_code": "0x0",
    "session_id": 0,
    "tree_id": 0,
    "client_dialects": [
      "2.02",
      "2.10"
    ],
    "client_guid": "601985d2-aad9-11e7-8494-00088bb57f27",
    "server_guid": "aec6e793-2b11-4019-2d95-55453a0ad2f1"
  }

SMB1 partial SMB1_COMMAND_SESSION_SETUP_ANDX::

    "request": {
      "native_os": "Unix",
      "native_lm": "Samba 3.9.0-SVN-build-11572"
    },
    "response": {
      "native_os": "Windows (TM) Code Name \"Longhorn\" Ultimate 5231",
      "native_lm": "Windows (TM) Code Name \"Longhorn\" Ultimate 6.0"
    }

DCERPC fields
~~~~~~~~~~~~~

* "request" (string): command. E.g. REQUEST, BIND.
* "response" (string): reply. E.g. RESPONSE, BINDACK or FAULT.
* "opnum" (integer): the opnum
* "call_id" (integer): the call id
* "frag_cnt" (integer): the number of fragments for the stub data
* "stub_data_size": total stub data size
* "interfaces" (array): list of interfaces
* "interfaces.uuid" (string): string representation of the UUID
* "interfaces.version" (string): interface version
* "interfaces.ack_result" (integer): ack result
* "interfaces.ack_reason" (integer): ack reason


DCERPC REQUEST/RESPONSE::

  "smb": {
    "id": 4,
    "dialect": "unknown",
    "command": "SMB2_COMMAND_IOCTL",
    "status": "STATUS_SUCCESS",
    "status_code": "0x0",
    "session_id": 4398046511201,
    "tree_id": 0,
    "dcerpc": {
      "request": "REQUEST",
      "response": "RESPONSE",
      "opnum": 0,
      "req": {
        "frag_cnt": 1,
        "stub_data_size": 136
      },
      "res": {
        "frag_cnt": 1,
        "stub_data_size": 8
      },
      "call_id": 2
    }
  }

DCERPC BIND/BINDACK::

  "smb": {
    "id": 53,
    "dialect": "2.10",
    "command": "SMB2_COMMAND_WRITE",
    "status": "STATUS_SUCCESS",
    "status_code": "0x0",
    "session_id": 35184439197745,
    "tree_id": 1,
    "dcerpc": {
      "request": "BIND",
      "response": "BINDACK",
      "interfaces": [
        {
          "uuid": "12345778-1234-abcd-ef00-0123456789ac",
          "version": "1.0",
          "ack_result": 2,
          "ack_reason": 0
        },
        {
          "uuid": "12345778-1234-abcd-ef00-0123456789ac",
          "version": "1.0",
          "ack_result": 0,
          "ack_reason": 0
        },
        {
          "uuid": "12345778-1234-abcd-ef00-0123456789ac",
          "version": "1.0",
          "ack_result": 3,
          "ack_reason": 0
        }
      ],
      "call_id": 2
    }

NTLMSSP fields
~~~~~~~~~~~~~~

* "domain" (string): the Windows domain.
* "user" (string): the user.
* "host" (string): the host.

Example::

    "ntlmssp": {
      "domain": "VNET3",
      "user": "administrator",
      "host": "BLU"
    }

More complete example::

  "smb": {
    "id": 3,
    "dialect": "NT LM 0.12",
    "command": "SMB1_COMMAND_SESSION_SETUP_ANDX",
    "status": "STATUS_SUCCESS",
    "status_code": "0x0",
    "session_id": 2048,
    "tree_id": 0,
    "ntlmssp": {
      "domain": "VNET3",
      "user": "administrator",
      "host": "BLU"
    },
    "request": {
      "native_os": "Unix",
      "native_lm": "Samba 3.9.0-SVN-build-11572"
    },
    "response": {
      "native_os": "Windows (TM) Code Name \"Longhorn\" Ultimate 5231",
      "native_lm": "Windows (TM) Code Name \"Longhorn\" Ultimate 6.0"
    }
  }

Kerberos fields
~~~~~~~~~~~~~~~

* "kerberos.realm" (string): the Kerberos Realm.
* "kerberos.snames (array of strings): snames.

Example::

  "smb": {
    "dialect": "2.10",
    "command": "SMB2_COMMAND_SESSION_SETUP",
    "status": "STATUS_SUCCESS",
    "status_code": "0x0",
    "session_id": 35184439197745,
    "tree_id": 0,
    "kerberos": {
      "realm": "CONTOSO.LOCAL",
      "snames": [
        "cifs",
        "DC1.contoso.local"
      ]
    }
  }


Event type: SSH
----------------

Fields
~~~~~~

* "proto_version": The protocol version transported with the ssh protocol (1.x, 2.x)
* "software_version": The software version used by end user

Example of SSH logging:

::

  "ssh": {
    "client": {
        "proto_version": "2.0",
        "software_version": "OpenSSH_6.7",
     },
    "server": {
        "proto_version": "2.0",
        "software_version": "OpenSSH_6.7",
     }
  }

Event type: Flow
----------------

Fields
~~~~~~

* "pkts_toserver": total number of packets to server, include bypassed packets
* "pkts_toclient": total number of packets to client
* "bytes_toserver": total bytes count to server
* "bytes_toclient": total bytes count to client
* "bypassed.pkts_toserver": number of bypassed packets to server
* "bypassed.pkts_toclient": number of bypassed packets to client
* "bypassed.bytes_toserver": bypassed bytes count to server
* "bypassed.bytes_toclient": bypassed bytes count to client
* "start": date of start of the flow
* "end": date of end of flow (last seen packet)
* "age": duration of the flow
* "bypass": if the flow has been bypassed, it is set to "local" (internal bypass) or "capture"
* "state": display state of the flow (include "new", "established", "closed", "bypassed")
* "reason": mechanism that did trigger the end of the flow (include "timeout", "forced" and "shutdown")
* "alerted": "true" or "false" depending if an alert has been seen on flow

Example ::

  "flow": {
    "pkts_toserver": 23,
    "pkts_toclient": 21,
    "bytes_toserver": 4884,
    "bytes_toclient": 7392,
    "bypassed": {
      "pkts_toserver": 10,
      "pkts_toclient": 8,
      "bytes_toserver": 1305,
      "bytes_toclient": 984
    },
    "start": "2019-05-28T23:32:29.025256+0200",
    "end": "2019-05-28T23:35:28.071281+0200",
    "age": 179,
    "bypass": "capture",
    "state": "bypassed",
    "reason": "timeout",
    "alerted": false
  }

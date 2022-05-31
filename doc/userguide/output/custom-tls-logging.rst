Custom tls logging
===================

In your Suricata.yaml, find the tls-log section and edit as follows:

::

  - tls-log:
      enabled: yes      # Log TLS connections.
      filename: tls.log # File to store TLS logs.
      append: yes
      custom: yes       # enabled the custom logging format (defined by customformat)
      customformat: "%{%D-%H:%M:%S}t.%z %a:%p -> %A:%P %v %n %d %D"

And in your tls.log file you would get the following, for example:

::

 12/03/16-19:20:14.85859 10.10.10.4:58274 -> 192.0.78.24:443 VERSION='TLS 1.2' suricata-ids.org NOTBEFORE='2016-10-27T20:36:00' NOTAFTER='2017-01-25T20:36:00'

The list of supported format strings is the following:

* %n - client SNI
* %v - TLS/SSL version
* %d - certificate date not before
* %D - certificate date not after
* %f - certificate fingerprint SHA1
* %s - certificate subject
* %i - certificate issuer dn
* %E - extended format
* %{strftime_format}t - timestamp of the TLS transaction in the selected strftime format. ie: 08/28/12-22:14:30
* %z - precision time in useconds. ie: 693856
* %a - client IP address
* %p - client port number
* %A - server IP address
* %P - server port number

Any non printable character will be represented by its byte value in hexadecimal format (\|XX\|, where XX is the hex code)

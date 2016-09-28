Custom http logging
===================

As of Suricata 1.3.1 you can enable a custom http logging option.

In your Suricata.yaml, find the http-log section and edit as follows:


::


  - http-log:
        enabled: yes
        filename: http.log
        custom: yes # enable the custom logging format (defined by custom format)
        customformat: "%{%D-%H:%M:%S}t.%z %{X-Forwarded-For}i %{User-agent}i %H %m %h %u %s %B %a:%p -> %A:%P"
        append: no
        #extended: yes     # enable this for extended logging information
        #filetype: regular # 'regular', 'unix_stream' or 'unix_dgram'

And in your http.log file you would get the following, for example:

::

 8/28/12-22:14:21.101619 - Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:11.0) Gecko/20100101 Firefox/11.0  HTTP/1.1 GET us.cnn.com /video/data/3.0/video/world/2012/08/28/hancocks-korea-typhoon-bolavan.cnn/index.xml 200 16856 192.168.1.91:45111 -> 157.166.255.18:80

::

 08/28/12-22:14:30.693856 - Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:11.0) Gecko/20100101 Firefox/11.0  HTTP/1.1 GET us.cnn.com /video/data/3.0/video/showbiz/2012/08/28/conan-reports-from-rnc-convention.teamcoco/index.xml 200 15789 192.168.1.91:45108 -> 157.166.255.18:80

The list of supported format strings is the following:

* %h - Host HTTP Header (remote host name). ie: google.com
* %H - Request Protocol. ie: HTTP/1.1
* %m - Request Method. ie: GET
* %u - URL including query string. ie: /search?q=suricata
* %{header_name}i - contents of the defined HTTP Request Header name. ie:

 * %{User-agent}i: Mozilla/5.0 (X11; Ubuntu; Linux i686; rv:11.0) Gecko/20100101 Firefox/11.0
 * %{X-Forwarded-For}i: outputs the IP address contained in the X-Forwarded-For HTTP header (inserted by a reverse proxy)

* %s - return status code. In the case of 301 and 302 it will print the url in brackets. ie: 200
* %B - response size in bytes. ie: 15789
* %{header_name}o - contents of the defined HTTP Response Header name
* %{strftime_format]t - timestamp of the HTTP transaction in the selected strftime format. ie: 08/28/12-22:14:30
* %z - precision time in useconds. ie: 693856
* %a - client IP address
* %p - client port number
* %A - server IP address
* %P - server port number

Any non printable character will be represented by its byte value in hexadecimal format (\|XX\|, where XX is the hex code)

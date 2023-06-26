>>>
GET /robots.txt HTTP/1.1
Host: nghttp2.org
User-Agent: curl/7.61.0
Accept: */*
Connection: Upgrade, HTTP2-Settings
Upgrade: h2c
HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA


<<<
HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 12

Hello World!


>>>
GET /robots.txt HTTP/1.1
Host: nghttp2.org
User-Agent: curl/7.61.0
Accept: */*
Connection: Upgrade, HTTP2-Settings
Upgrade: h2c
HTTP2-Settings: AAMAAABkAARAAAAAAAIAAAAA


<<<
HTTP/1.1 101 Switching Protocols
Connection: Upgrade
Upgrade: h2c


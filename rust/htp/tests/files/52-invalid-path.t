>>>
GET invalid/path?p=%20 HTTP/1.0
Host: [::1]:8080
User-Agent: Mozilla


<<<
HTTP/1.0 200 OK
Date: Mon, 31 Aug 2009 20:25:50 GMT
Server: Apache
Connection: close
Content-Type: text/html
Content-Length: 12

Hello World!
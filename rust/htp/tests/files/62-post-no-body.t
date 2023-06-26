>>>
POST / HTTP/1.0
Content-Length: 0
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla


<<<
HTTP/1.0 200 OK
Date: Mon, 31 Aug 2009 20:25:50 GMT
Server: Apache
Connection: close
Content-Type: text/html
Content-Length: 12

Hello World!
>>>
GET / HTTP/1.0


<<<
HTTP/1.0 200 OK
Date: Mon, 31 Aug 2009 20:25:50 GMT
Server: Apache
Connection: close
Content-Type: text/html
Transfer-Encoding: chunked

9
012345678
1
9
0


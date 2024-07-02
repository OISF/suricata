>>>
GET http://example.com/1 HTTP/1.1
Host: example.com


<<<
HTTP/1.1 200 OK
Date: Mon, 26 Apr 2010 13:56:31 GMT
Content-Length: 8

12345678
>>>
GET http://example.com/2 HTTP/1.1
Host: foo.com


<<<
HTTP/1.1 200 OK
Date: Mon, 26 Apr 2010 13:56:31 GMT
Content-Length: 8

12345678
>>>
POST http://www.example.com:8001/3 HTTP/1.1
Host: www.example.com:8001
Content-Length: 8

12345678
<<<
HTTP/1.1 200 OK
Date: Mon, 26 Apr 2010 13:56:31 GMT
Content-Length: 8

12345678
>>>
POST http://www.example.com:8002/4 HTTP/1.1
Host: www.example.com:8003
Content-Length: 8

12345678
<<<
HTTP/1.1 200 OK
Date: Mon, 26 Apr 2010 13:56:31 GMT
Content-Length: 8

12345678
>>>
POST http://www.example.com:80/5 HTTP/1.1
Host: www.example.com
Content-Length: 8

12345678
<<<
HTTP/1.1 200 OK
Date: Mon, 26 Apr 2010 13:56:31 GMT
Content-Length: 8

12345678
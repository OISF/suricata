>>>
PUT /forbidden HTTP/1.1
Content-Length: 14
Expect: 100-continue


<<<
HTTP/1.0 401 Forbidden
Content-Length: 0


>>>
POST /ok HTTP/1.1
Content-Length: 14
Expect: 100-continue


<<<
HTTP/1.0 100 continue
Content-Length: 0


>>>
Hello People!

<<<
HTTP/1.0 200 OK

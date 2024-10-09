>>>
POST / HTTP/1.1
Host: localhost
Content-Type: application/x-www-form-urlencoded

login=foo&password=bar

<<<
HTTP/1.1 200 OK
Content-Length: 0 


>>>
GET / HTTP/1.1
Host: localhost


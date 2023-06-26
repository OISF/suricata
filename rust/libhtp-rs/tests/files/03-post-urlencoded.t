>>>
POST /?qsp1=1&%20p%20q=2&u=Ivan+Risti%C4%87_Ivan+Risti%C4%87_Ivan+Risti%C4%87_Ivan+Risti%C4%87_Ivan+Risti%C4%87_Ivan+Risti%C4%87_ HTTP/1.0
Content-Length: 12
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla

p=0123456789
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


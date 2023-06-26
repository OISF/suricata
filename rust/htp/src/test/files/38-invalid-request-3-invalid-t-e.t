>>>
POST / HTTP/1.1
Transfer-Encoding: ABC
Host: www.example.com
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla
Cookie: 1

b
p=012345678
1
9
0
Cookie:
>>>
 2


<<<
HTTP/1.0 200 OK
Date: Mon, 31 Aug 2009 20:25:50 GMT
Server: Apache
Connection: close
Content-Type: text/html
Content-Length: 12

Hello World!
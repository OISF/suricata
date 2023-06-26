>>>
GET / HTTP/1.1
Host: www.example.com


<<<
HTTP/1.0 200 OK
Content-Length: 12

Hello World!
>>>
GET / HTTP/1.1
Host: www.example.com.


<<<
HTTP/1.0 200 OK
Content-Length: 12
>>>
GET / HTTP/1.1
Host: WwW.ExamPle.cOm


<<<
HTTP/1.0 200 OK
Content-Length: 12
>>>
GET / HTTP/1.1
Host: www.example.com:80


<<<
HTTP/1.0 200 OK
Content-Length: 12
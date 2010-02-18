>>>
GET http://www.example%64.com/one/two/three.php?p=%64&q=%64#fff HTTP/1.0


<<<
HTTP/1.1 200 OK
Content-Type: text/html
Content-Length: 12

Hello World!
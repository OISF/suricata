>>>
POST / HTTP/1.1
User-Agent: curl/7.18.2 (i486-pc-linux-gnu) libcurl/7.18.2 OpenSSL/0.9.8g zlib/1.2.3.3 libidn/1.8 libssh2/0.18
Accept: */*
Content-Length: 216
Expect: 100-continue
Content-Type: multipart/form-data; boundary=----------------------------07869933ca1b


<<<
HTTP/1.1 100 Continue
Header1: This
Header2: That


>>>
------------------------------07869933ca1b
Content-Disposition: form-data; name="file"; filename="404.php"
Content-Type: application/octet-stream


>>>
<? echo "404"; ?>
>>>

------------------------------07869933ca1b--

<<<
HTTP/1.1 200 OK
Date: Tue, 03 Nov 2009 09:27:47 GMT
Server: Apache
Last-Modified: Thu, 30 Apr 2009 12:20:49 GMT
ETag: "2dcada-2d-468c4b9ec6a40"
Accept-Ranges: bytes
Content-Length: 45
Vary: Accept-Encoding
Content-Type: text/html

<html><body><h1>It works!</h1></body></html>

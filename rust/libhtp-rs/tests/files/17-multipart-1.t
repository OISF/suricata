>>>
POST /upload.php?qsp1=1&%20p%20q=2 HTTP/1.1
Host: 192.168.3.100:8080
User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.9.1.7) Gecko/20091221 Firefox/3.5.7 (.NET CLR 3.5.30729)
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-us,en;q=0.5
Accept-Encoding: gzip,deflate
Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7
Keep-Alive: 300
Connection: keep-alive
Content-Type: multipart/form-data; boundary=---------------------------41184676334
Content-Length: 610

-----------------------------41184676334
Content-Disposition: form-data; name="field1"

0123456789
-----------------------------41184676334
Content-Disposition: form-data; name="field2"

9876543210
-----------------------------41184676334
Content-Disposition: form-data; name="file1"; filename="New Text Document.txt"
Content-Type: text/plain

FFFFFFFFFFFFFFFFFFFFFFFFFFFF
-----------------------------41184676334
Content-Disposition: form-data; name="file2"; filename="New Text Document.txt"
Content-Type: text/plain

FFFFFFFFFFFFFFFFFFFFFFFFFFFF
-----------------------------41184676334--

<<<
HTTP/1.0 200 OK
Date: Mon, 31 Aug 2009 20:25:50 GMT
Server: Apache
Connection: close
Content-Type: text/html

Hello World!
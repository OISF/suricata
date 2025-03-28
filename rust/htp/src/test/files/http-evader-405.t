>>>
GET /broken/eicar.txt/chunked;lfcr-no-crlf;end-crlfcrlf HTTP/1.1
Host: evader.example.com


<<<
HTTP/1.1 200 ok
Content-type: application/octet-stream
Content-disposition: attachment; filename="eicar.txt"
Connection: close
Transfer-Encoding: chunked
Yet-another-header: foo

4
X5O!
4
P%@A
4
P[4\
4
PZX5
4
4(P^
4
)7CC
4
)7}$
4
EICA
4
R-ST
4
ANDA
4
RD-A
4
NTIV
4
IRUS
4
-TES
4
T-FI
4
LE!$
4
H+H*
0


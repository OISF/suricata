>>>
GET /broken/eicar.txt/end-lf%5C040lf HTTP/1.1
Host: evader.example.com


<<<
HTTP/1.1 200 ok
Content-type: application/octet-stream
Content-disposition: attachment; filename="eicar.txt"
Connection: close
Yet-another-header: foo
Content-length: 68
 
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*

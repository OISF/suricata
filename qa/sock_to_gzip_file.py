#!/usr/bin/python
#I love the python Power Glove. It's so bad!
#Usage: sudo -u suricata ./sock_to_gzip_file.py --output-file="http.log.gz" --listen-sock="http.log.sock"

import socket,os
import gzip
import sys
from optparse import OptionParser

if __name__ == "__main__":
    parser = OptionParser()
    #Path to the socket
    parser.add_option("--listen-sock", dest="lsock", type="string", help="Path to the socket we will listen on.")
    #Path to gzip file we will write
    parser.add_option("--output-file", dest="output", type="string", help="Path to file name to output gzip file we will write to.")

    #parse the opts
    (options, args) = parser.parse_args()

    options.usage = "example: sudo -u suricata ./sock_to_gzip_file.py --output-file=\"http.log.gz\" --listen-sock=\"http.log.sock\"\n"
    #Open the output file
    if options.output:
        try:
            f = gzip.open(options.output, 'wb')
        except Exception,e:
            print("Error: could not open output file %s:\n%s\n", options.output, e)
            sys.exit(-1)
    else:
        print("Error: --output-file option required and was not specified\n%s" % (options.usage))
        sys.exit(-1)

    #Open our socket and bind
    if options.lsock:
        if os.path.exists(options.lsock):
            try:
                os.remove(options.lsock)
            except OSError:
                pass
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.bind(options.lsock)
            s.listen(1)
            conn, addr = s.accept()
        except Exception,e:
            print("Error: Failed to bind socket %s\n%s\n", options.lsock, e)
            sys.exit(-1)
    else:
        print("Error: --listen-sock option required and was not specified\n%s" % (options.usage))
        sys.exit(-1)

    #Read data from the socket and write to the file
    while 1:
        data = conn.recv(1024)
        if not data: break
        f.write(data)
    conn.close()
    f.close()

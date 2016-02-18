What to do with files-json.log output
=====================================

.. toctree::

   script-follow-json
   mysql
   postgresql
   useful-queries-for-mysql-and-postgresql
   mongodb
   logstash-kibana-and-suricata-json-output

Suricata has the ability to produce the files-json.log output.
Basically this is a JSON style format output logfile with entries like this:

::

 {
 "timestamp": "10\/01\/2012-16:52:59.217616",
 "ipver": 4,
 "srcip": "80.239.217.171",
 "dstip": "192.168.42.197",
 "protocol": 6,
 "sp": 80,
 "dp": 32982,
 "http_uri": "\/frameworks\/barlesque\/2.11.0\/desktop\/3.5\/style\/main.css", "http_host": "static.bbci.co.uk", "http_referer": "http:\/\/www.bbc.com\/", "filename": "\/frameworks\/barl
 esque\/2.11.0\/desktop\/3.5\/style\/main.css",
 "magic": "ASCII text, with very long lines, with no line terminators",
 "state": "CLOSED",
 "md5": "be7db5e9a4416a4123d556f389b7f4b8",
 "stored": false,
 "size": 29261
 }

for every single file that crossed your http pipe.
This in general is very helpful and informative.
In this section we are going to try to explore/suggest approaches for putting it to actual use, since it could aggregate millions of entries in just a week.
There are a god few options in general since the JSON style format is pretty common.
http://www.json.org/


This guide offers a couple of approaches -
use of custom created script with MySQL or PostgreSQL import (bulk or continuous)
or importing it directly to MongoDB(native import of JSON files).

Please read the all the pages before you jump into executing scripts and/or installing/configuring things.
Te guide is written using Ubuntu LTS server 12.04

Thee are 3 options in general that we suggest, that we are going to explain here:

1. import JSON into MySQL
2. import JSON into PostgreSQL
3. import JSON into MongoDB

The suggested approach is
configure Suricata.yaml
configure your Database
run the script (not applicable to MongoDB)
and then execute queries against the DB to get the big picture.


Peter Manev

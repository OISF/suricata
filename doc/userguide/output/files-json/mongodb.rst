MongoDB
=======

If you do not have it installed, follow the istructions here:
http://docs.mongodb.org/manual/tutorial/install-mongodb-on-ubuntu/

Basically you do:


::


  sudo apt-key adv --keyserver keyserver.ubuntu.com --recv 7F0CEB10
  deb http://downloads-distro.mongodb.org/repo/ubuntu-upstart dist 10gen
  sudo apt-get update && sudo apt-get install mongodb-10gen


The bigest benefit of MongoDB is that it can natively import json.log files:
if you have MongoDB installed - all you have to do is:


::


  mongoimport --db filejsondb --collection filejson --file files-json.log

here:

* --db filejsondb is the database,
* --collections filejson is the equivalent of SQL "table"
* --file files-json.log  - is the json log created and logged into from Suricata.

last but not least - it would automatically create the db and tables for you.

this would import a 5 Gb (15 million entries) json log file in about 5-10 minutes - default configuration, without tuning MongoDB for high performance. (your set up and HW will definitely have effect on the import time )



MongoDB Example queries (once you have imported the files-json.log - described above - just go ahead with these queries):


::


  db.files.group( { cond : {"magic":/.*PDF*./ }, key: {"srcip":true,"http_host":true,"magic":true} ,initial: {count: 0},reduce: function(value, total) {total+=value.count;} } );


::


  db.filejson.find({magic:/.*PDF.*/},{srcip:1,http_host:1,magic:1}).sort({srcip:1,http_host:1,magic:1}).limit(20)


Get a sorted table biggest to smallest number hosts of  file downloads:


::


  > map = function () { emit({srcip:this.srcip,http_host:this.http_host,magic:this.magic}, {count:1}); }
  function () {
     emit({srcip:this.srcip, http_host:this.http_host, magic:this.magic}, {count:1});
  }
  > reduce = function(k, values) {var result = {count: 0}; values.forEach(function(value) { result.count += value.count; }); return result; }
  function (k, values) {
     var result = {count:0};
     values.forEach(function (value) {result.count += value.count;});
     return result;
  }
  > db.filejson.mapReduce(map,reduce,{out: "myoutput"  });
  {
      "result" : "myoutput",
      "timeMillis" : 578806,
      "counts" : {
          "input" : 3110871,
          "emit" : 3110871,
          "reduce" : 673186,
          "output" : 219840
      },
      "ok" : 1,
  }
  > db.myoutput.find().sort({'value.count':-1}).limit(10)
  { "_id" : { "srcip" : "184.107.x.x", "http_host" : "arexx.x", "magic" : "very short file (no magic)" }, "value" : { "count" : 42560 } }
  { "_id" : { "srcip" : "66.135.210.182", "http_host" : "www.ebay.co.uk", "magic" : "XML document text" }, "value" : { "count" : 30896 } }
  { "_id" : { "srcip" : "66.135.210.62", "http_host" : "www.ebay.co.uk", "magic" : "XML document text" }, "value" : { "count" : 27812 } }
  { "_id" : { "srcip" : "213.91.x.x", "http_host" : "www.focxxxx.x", "magic" : "HTML document, ISO-8859 text" }, "value" : { "count" : 26301 } }
  { "_id" : { "srcip" : "195.168.x.x", "http_host" : "search.etaxxx.x", "magic" : "JPEG image data, JFIF standard 1.01, comment: \"CREATOR: gd-jpeg v1.0 (using IJG JPEG v80), quality = 100\"" }, "value" : { "count" : 16131 } }
  { "_id" : { "srcip" : "184.107.x.x", "http_host" : "p2p.arxx.x:2710", "magic" : "ASCII text, with no line terminators" }, "value" : { "count" : 15829 } }
  { "_id" : { "srcip" : "213.91.x.x", "http_host" : "www.focxx.x", "magic" : "HTML document, ISO-8859 text" }, "value" : { "count" : 14472 } }
  { "_id" : { "srcip" : "64.111.199.222", "http_host" : "syndication.exoclick.com", "magic" : "HTML document, ASCII text, with very long lines, with no line terminators" }, "value" : { "count" : 14009 } }
  { "_id" : { "srcip" : "69.171.242.70", "http_host" : "www.facebook.com", "magic" : "ASCII text, with no line terminators" }, "value" : { "count" : 13098 } }
  { "_id" : { "srcip" : "69.171.242.74", "http_host" : "www.facebook.com", "magic" : "ASCII text, with no line terminators" }, "value" : { "count" : 12801 } }
  >



Peter Manev

Filemd5 and white or black listing with MD5 hashes
==================================================



This guide will show you how to set up a white/black MD5 listing using latest Suricata on Ubuntu LTS 12.04 64 bit
and a file containing 87 million MD5s  - white list.


In this set up we had/did the following :

1. A Suricata installation with :doc:`md5` enabled.
2. We start Suricata with about 4.5K rules and the MD5 white list file containing 87 million MD5 entries.
3. We have a 9.5Gb of traffic.
4. We have the following set up:

  
::

  
      CPU: One Intel(R) Xeon(R) CPU E5-2680 0 @ 2.70GHz (16 cores counting Hyperthreading)
      Memory: 32Gb
      capture NIC: Intel 82599EB 10-Gigabit SFI/SFP+
  


You need to get the white list file containing MD5s from here - http://www.nsrl.nist.gov/Downloads.htm
This is an official database containing  SHA-1 and MD5s for files that are " traceable ".
For example after you download and unzip (I used the Combo DVD link) you would get a file like so:

  
::

  
  
  "SHA-1","MD5","CRC32","FileName","FileSize","ProductCode","OpSystemCode","SpecialCode"
  "000000206738748EDD92C4E3D2E823896700F849","392126E756571EBF112CB1C1CDEDF926","EBD105A0","I05002T2.PFB",98865,3095,"WIN",""
  "0000004DA6391F7F5D2F7FCCF36CEBDA60C6EA02","0E53C14A3E48D94FF596A2824307B492","AA6A7B16","00br2026.gif",2226,228,"WIN",""
  "000000A9E47BD385A0A3685AA12C2DB6FD727A20","176308F27DD52890F013A3FD80F92E51","D749B562","femvo523.wav",42748,4887,"MacOSX",""
  "00000142988AFA836117B1B572FAE4713F200567","9B3702B0E788C6D62996392FE3C9786A","05E566DF","J0180794.JPG",32768,16848,"358",""
  "00000142988AFA836117B1B572FAE4713F200567","9B3702B0E788C6D62996392FE3C9786A","05E566DF","J0180794.JPG",32768,18266,"358",""
  "00000142988AFA836117B1B572FAE4713F200567","9B3702B0E788C6D62996392FE3C9786A","05E566DF","J0180794.JPG",32768,20316,"358",""
  "00000142988AFA836117B1B572FAE4713F200567","9B3702B0E788C6D62996392FE3C9786A","05E566DF","J0180794.JPG",32768,20401,"358",""
  "00000142988AFA836117B1B572FAE4713F200567","9B3702B0E788C6D62996392FE3C9786A","05E566DF","J0180794.JPG",32768,2322,"WIN",""
  "00000142988AFA836117B1B572FAE4713F200567","9B3702B0E788C6D62996392FE3C9786A","05E566DF","J0180794.JPG",32768,23822,"358",""
  

The file contains 87 million entries/lines, each line having 
"SHA-1","MD5","CRC32","FileName","FileSize","ProductCode","OpSystemCode","SpecialCode"
of a traceable file.

You can use the Linux "cut" utility to make this file into only a MD5 file - have only the MD5 check sums (second row) - which is what we need.
Here is what you can do:

Download the ComboDVD - http://www.nsrl.nist.gov/RDS/rds_2.47/RDS_247.iso

unzip/tar, then 
  
::

  
  cat NSRFile.txt | more

would be able to see the beginning of the file and get an idea of what does it contain.(shown above)
**NOTE – this is a 10GB file, make sure you have the space!**

the MD5 column ... should start with "MD5"

  
::

  
  sudo cut -d'"' -f4 NSRFile.txt >> MD5.txt

and you have only MD5s ...but still with "MD5" on top

  
::

  
  sed -i '1d'  MD5.txt

wait for a while
check the file 

  
::

  
  wc -l MD5.txt

wait for about 2-3 min

should be about 87Mil something md5s , one per line
**NOTE:**
You can also import the file into a MySQL database, if you would like:

  
::

  
  mysql> create user 'filejson'@'localhost' IDENTIFIED BY 'PASSWORD123';
  Query OK, 0 rows affected (0.00 sec)
  
  mysql>create database filejsondb;
  mysql> grant all privileges on filejsondb.* to 'filejson'@'localhost' with grant option;
  mysql>  flush privileges;
  mysql> use filejsondb;
  
Then:
  
::

  
  CREATE TABLE MD5(md5_whitelist VARCHAR(32));

The trick here for the import is that **the table name and the file name MUST be the same** - aka MySQL table "MD5" and the file is called MD5.txt!
  
::

  
  sudo mysqlimport -u root -p --local filejsondb MD5.txt

Where "filejsondb" is the name of the database.



So , here is how we did it  ....


  
::

  
  pevman@suricata:~$ ls -lh /etc/suricata/et-config/MD5_NSRFile.txt 
  -rw-r--r-- 1 root root 2.7G Aug 29 00:35 /etc/suricata/et-config/MD5_NSRFile.txt
  
  pevman@suricata:~$ wc -l  /etc/suricata/et-config/MD5_NSRFile.txt 
  87345542 /etc/suricata/et-config/MD5_NSRFile.txt
  pevman@suricata:~$ 
  




  
::

  
  pevman@suricata:~$ sudo tcpstat -i eth3
  Time:1346241952	n=6664547	avg=898.01	stddev=757.68	bps=9575769952.00
  Time:1346241957	n=6670750	avg=897.22	stddev=754.07	bps=9576254160.00
  Time:1346241962	n=6626520	avg=903.62	stddev=747.26	bps=9580577822.40
  Time:1346241967	n=6685956	avg=895.15	stddev=749.34	bps=9575883715.20
  Time:1346241972	n=6712481	avg=891.53	stddev=747.34	bps=9575027134.40
  Time:1346241977	n=6696189	avg=893.82	stddev=746.62	bps=9576294273.60
  Time:1346241982	n=6681826	avg=895.75	stddev=749.67	bps=9576376033.60
  



  
::

  
  pevman@suricata:~$ suricata --build-info
  [2746] 29/8/2012 -- 15:07:25 - (suricata.c:539) <Info> (SCPrintBuildInfo) -- This is Suricata version 1.4dev (rev 75af345)
  [2746] 29/8/2012 -- 15:07:25 - (suricata.c:612) <Info> (SCPrintBuildInfo) -- Features: PCAP_SET_BUFF LIBPCAP_VERSION_MAJOR=1 AF_PACKET HAVE_PACKET_FANOUT LIBCAP_NG LIBNET1.1 HAVE_HTP_URI_NORMALIZE_HOOK HAVE_HTP_TX_GET_RESPONSE_HEADERS_RAW HAVE_NSS 
  [2746] 29/8/2012 -- 15:07:25 - (suricata.c:626) <Info> (SCPrintBuildInfo) -- 64-bits, Little-endian architecture
  [2746] 29/8/2012 -- 15:07:25 - (suricata.c:628) <Info> (SCPrintBuildInfo) -- GCC version 4.6.3, C version 199901
  [2746] 29/8/2012 -- 15:07:25 - (suricata.c:634) <Info> (SCPrintBuildInfo) -- __GCC_HAVE_SYNC_COMPARE_AND_SWAP_1
  [2746] 29/8/2012 -- 15:07:25 - (suricata.c:637) <Info> (SCPrintBuildInfo) -- __GCC_HAVE_SYNC_COMPARE_AND_SWAP_2
  [2746] 29/8/2012 -- 15:07:25 - (suricata.c:640) <Info> (SCPrintBuildInfo) -- __GCC_HAVE_SYNC_COMPARE_AND_SWAP_4
  [2746] 29/8/2012 -- 15:07:25 - (suricata.c:643) <Info> (SCPrintBuildInfo) -- __GCC_HAVE_SYNC_COMPARE_AND_SWAP_8
  [2746] 29/8/2012 -- 15:07:25 - (suricata.c:646) <Info> (SCPrintBuildInfo) -- __GCC_HAVE_SYNC_COMPARE_AND_SWAP_16
  [2746] 29/8/2012 -- 15:07:25 - (suricata.c:650) <Info> (SCPrintBuildInfo) -- compiled with -fstack-protector
  [2746] 29/8/2012 -- 15:07:25 - (suricata.c:656) <Info> (SCPrintBuildInfo) -- compiled with _FORTIFY_SOURCE=2

During Suricata start up :
...
  
::

  
  [3071] 29/8/2012 -- 15:23:45 - (detect.c:670) <Info> (SigLoadSignatures) -- Loading rule file: /var/data/peter/md5test.rules
  [3071] 29/8/2012 -- 15:23:45 - (detect-filemd5.c:105) <Error> (Md5ReadString) -- [ERRCODE: SC_ERR_INVALID_MD5(214)] - md5 string not 32 bytes
  [3071] 29/8/2012 -- 15:24:25 - (detect-filemd5.c:277) <Info> (DetectFileMd5Parse) -- MD5 hash size 1399625840 bytes, negated match
  [3071] 29/8/2012 -- 15:24:25 - (detect.c:701) <Info> (SigLoadSignatures) -- 5 rule files processed. 4641 rules succesfully loaded, 0 rules failed


You will get the
  
::

  [ERRCODE: SC_ERR_INVALID_MD5(214)] - md5 string not 32 bytes  

if  a line of the file is not containing a proper MD5 hash.

For example above we get the err message (which is more of a warning) because in the file , the first line was containing:
"SHA-1","MD5","CRC32","FileName","FileSize","ProductCode","OpSystemCode","SpecialCode"

However , nonetheless Suricata will continue loading the rest of the MD5 hashes from the file. REMEMBER - you would need put only the MD5 hashes in the file.


Then we just created the following test rules:
  
::

  
  root@suricata:/etc/suricata/peter-yaml# cat /var/data/peter/md5test.rules 
  alert http any any -> any any (msg:"FILE MD5 Check PDF against a white list"; filemagic:"pdf"; filemd5:!MD5_NSRFile.txt; sid:9966699; rev:1;)
  alert http any any -> any any (msg:"FILE MD5 Check EXE against a white list"; filemagic:"exe"; filemd5:!MD5_NSRFile.txt; sid:9977799; rev:2;)

Make sure the **MD5_NSRFile.txt** file (containing the MD5 hashes) is in your "rules directory" (where you load the rules from).


Basically the two rules above are telling Suricata to do the following:
1. If you see a PDF document that has a MD5 hash NOT in the MD5_NSRFile.txt - generate an alert
2. If you see an EXE file that has a MD5 hash NOT in the MD5_NSRFile.txt - generate an alert

all that on the fly, while inspecting traffic.


Then all that is left is to start Suricata:
  
::

  
  sudo /usr/local/bin/suricata -c /etc/suricata/peter-yaml/suricata-af-packet-mmap.yaml -s /var/data/peter/md5test.rules --af-packet=eth3

and we get the alerts:

  
::

  
  08/29/2012-15:38:43.165038  [**] [1:9977799:2] FILE MD5 Check EXE against a white list [**] [Classification: (null)] [Priority: 3] {TCP} y.y.y.y:80 -> x.x.x.x:23836
  08/29/2012-15:39:32.551950  [**] [1:9977799:2] FILE MD5 Check EXE against a white list [**] [Classification: (null)] [Priority: 3] {TCP} y.y.y.y:2091 -> x.x.x.x:80
  


That's it.

You can reverse and use the above rules with a "blacklisting" of MD5 hashes, for example:

  
::

  
  alert http any any -> any any (msg:"FILE MD5 Check PDF against a black list"; filemagic:"pdf"; filemd5:BlackMD5s.txt; sid:9966699; rev:1;)

You can also use the filestore keyword to store the file on disk and  do further analysis on the particular file - or blend it in with other :doc:`../rules/file-keywords`.

Peter Manev



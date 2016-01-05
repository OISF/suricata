MySQL
=====

If you do not have MySQL installed - go ahead and do so:
  
::

  
  sudo apt-get update && sudo apt-get upgrade
  sudo apt-get install mysql-server mysql-client
  

For MySQL make sure you create a db and a table:

  
::

  
  mysql>create database filejsondb;
  mysql> create user 'filejson'@'localhost' IDENTIFIED BY 'PASSWORD123';
  Query OK, 0 rows affected (0.00 sec)
  mysql> grant all privileges on filejsondb.* to 'filejson'@'localhost' with grant option;
  mysql>  flush privileges;
  mysql> use filejsondb;
  
  mysql> CREATE TABLE filejson( time_received VARCHAR(64), ipver VARCHAR(4),  srcip VARCHAR(40), dstip VARCHAR(40), protocol SMALLINT UNSIGNED, sp SMALLINT UNSIGNED, dp SMALLINT UNSIGNED, http_uri TEXT, http_host TEXT, http_referer TEXT, filename TEXT, magic TEXT, state VARCHAR(32), md5 VARCHAR(32), stored VARCHAR(32), size BIGINT UNSIGNED);
  
  mysql> show columns  from filejson;



OPTIONALLY - if you would like you can add in the MD5 whitelist table and import the data as described here ( [[Filemd5 and white/black listing with MD5]] )

now you can go ahead and execute the script - [[Script FollowJSON]]

Peter Manev

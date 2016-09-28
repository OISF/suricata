PostgreSQL
==========

If you do not have  PostgreSQL installed:


::


  sudo apt-get update && sudo apt-get upgrade
  sudo apt-get install postgresql



::


  sudo vim /etc/postgresql/9.1/main/pg_hba.conf

change the line:


::


  local   all             all                                     trust

to


::


  local   all             all                                     md5


login and change passwords

::


  sudo -u postgres psql postgres
  \password postgres


Then -



::


  create database filejsondb;
  \c filejsondb;
  create user filejson with password 'PASSWORD123';
  CREATE TABLE filejson( time_received VARCHAR(64), ipver VARCHAR(4),  srcip VARCHAR(40), dstip VARCHAR(40), protocol INTEGER, sp INTEGER, dp INTEGER, http_uri TEXT, http_host TEXT, http_referer TEXT, filename TEXT, magic TEXT, state VARCHAR(32), md5 VARCHAR(32), stored VARCHAR(32), size BIGINT);
  grant all privileges on database filejsondb to filejson;

Log out and log in again (with the "filejson" user) to test if everything is ok:


::


  psql -d filejson -U filejson




Optionally you could create and import the MD5 white list data if you wish - generally the same guidance as described in :ref:`FileMD5 and white/black listing with md5 <filemd5-listing>`

Some more general info and basic commands/queries:
http://jazstudios.blogspot.se/2010/06/postgresql-login-commands.html
http://www.thegeekstuff.com/2009/05/15-advanced-postgresql-commands-with-examples/


now you can go ahead and execute the script - :ref:`Script FollowJSON <script-follow-json>`

Peter Manev

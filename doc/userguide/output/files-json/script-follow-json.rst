.. _script-follow-json:

Script FollowJSON
=================

BEFORE you run the script - make sure you have set up suricata.yaml and your database correctly !!

Suricata.yaml:

1. make sure json-log is enabled
2. and append is set to yes
3. optionally - you have compilled in Suricata with MD5's enabled

MD5's are enabled and forced in the suricata yaml config ( :ref:`MD5 <md5>` )
bottom of the page "Log all MD5s without any rules" .


::


  - file-log:
      enabled: yes
      filename: files-json.log
      append: yes
      #filetype: regular # 'regular', 'unix_stream' or 'unix_dgram'
      force-magic: yes   # force logging magic on all logged files
      force-md5: yes     # force logging of md5 checksums


**Append is set to yes** - this is very important if you "follow" , json.log - if you use the tool to constantly parse and insert logs from files-json.log as they are being written onto the log file.


There is a  python script (in BETA now and) available here:

* https://redmine.openinfosecfoundation.org/attachments/download/843/FollowJSON.tar.gz

that you can use for helping out in importing files-json.log entries into a MSQL or PostgreSQL database.

The script would allow you to do the following:


* it contains 2 files
* one python executable
* one yaml config file
* one LICENSE (GPLv2)

This is what the script does:

1. Multi-threaded  - spawns multiple processes if itself
2. uses yaml as configuration
3. Can:

    3.1. Read files-json.log file

        3.1.1. - Continuously  - as logs are being written in the log file
        3.1.2. - mass import a stand alone files-json.log into a database

    3.2. Into (your choice)

        3.2.1. MySQL DB (locally/remotely,ip)
        3.2.2. PostgreSQL DB (locally/remotely,ip)

4. Customizable number of processes (default is number of cores - if you have more then 16 - suggested value is NumCores/2)
5. Customizable "chunk" lines to read at once by every process - suggested (default) value is 10 (16 cores = 16 processes * 10 = 160 entries per second)

**Please look into the configurational yaml file** for more information.

The script is in BETA state - it has been tested , it works - but still, you should test it and adjust the configuration accordingly and run it on your test environment first before you put it in production.

After you have made:

#. your choices of database type (MySQL or PostgreSQL and installed/configured tables for it),
#. created the appropriate database structure and tables (explained in the next tutorial(s) ),
#. adjusted the yaml configuration accordingly,
#. started Suricata,

you would need:

::


  sudo apt-get install python-yaml python-mysqldb python-psycopg2

Then you just run the script, after you have started Suricata:


::


  sudo python Follow_JSON_Multi.py

if you would like to execute the script in the background:


::


  sudo python Follow_JSON_Multi.py &

Peter Manev

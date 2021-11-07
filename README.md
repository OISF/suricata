# Cloning and compiling this branch 

Cloning the repository:

```sudo git clone https://github.com/CosmoRied/suricata.git```

Change to this branch: 

```git checkout remotes/origin/mysql.```

Download the dependencies for compilation: 

```sudo apt-get -y install libpcre3 libpcre3-dbg libpcre3-dev build-essential autoconf automake libtool libpcap-dev libnet1-dev libyaml-0-2 libyaml-dev zlib1g zlib1g-dev libcap-ng-dev libcap-ng0 make libmagic-dev libjansson-dev libjansson4 pkg-config```

You need the mysql development libraries

```sudo apt-get install libmysqlclient-dev```

List the compiler flags necessary to compile suricata.

```mysql_config --cflags --libs```

They are:
```
-I/usr/include/mysql 
-L/usr/lib/x86_64-linux-gnu -lmysqlclient -lpthread -lz -lm -lrt -lssl -lcrypto -ldl -lresolv
```
Include these in the configure command used to compile suricata:

```
sudo ./configure LIBS="-L/usr/lib/x86_64-linux-gnu -lmysqlclient -lpthread -lz -lm -lrt -lssl -lcrypto -ldl -lresolv" CFLAGS="-I/usr/include/mysql"
```

**Fix issues in compilation:**

Fix any outstanding packages before completing the compilation. eg, cbindgen or libhtp...

eg. problem with **libhtp** not included.

In suricata directory execute: 

```
sudo git clone https://github.com/OISF/libhtp

Then back to compilation.

```
Continue to compile and install any missing packages, eg. missing cbindgen or rustc can throw an error.  

```
sudo apt-get install cbindgen rustc
```

**Install**

When the configure command completes succesfully...

```sudo make && sudo make install```

 **Check installed**:

Try and run suricata 

```sudo suricata```

Any issues with **libhtp.so** can be fixed: refer to this thread - https://forum.suricata.io/t/error-while-loading-shared-libraries-libhtp-so-2/734 

You now have a version of suricata that can load rules from a database. 

# Install suicata-update 

You need the modified suricata update utilty that inserts rules into the database here: https://github.com/CosmoRied/suricata-update

**Switch to mysql branch**

```
sudo git clone https://github.com/CosmoRied/suricata-update

# checkout the mysql branch

sudo git checkout remotes/origin/mysql

#Install the neccessary python connector

sudo apt-get install python3-mysql.connector

#Install the update utilty

sudo python3 setup.py install

```

Create database SURICATA if it doesnt exist in mysql

```
mysql -u root -p
CREATE DATABASE SURICATA;
```

**Setup a connection file in a directory in /etc/suricata/my.cnf**

Use the following configuration: 

```
[client]
database = SURICATA
user = user
password = password
default-character-set = utf8
```

# Load rules

Then load the rules using suricata-update with the special options to load using my.cnf connection parameter.

```sudo suricata-update --database --mysqlconf /etc/suricata/my.cnf```

That will load rules into the database you specified.

# Tell suricata to use database configuration files. 

In /usr/local/etc/suricata/suricata.yaml file, change the default path for rules files to the **database connection file** /etc/suricata/my.cnf

The /etc/suricata/my.cnf file should look like this:

```
default-rule-path: /etc/suricata/

rule-files:
  - my.cnf
```

# Start suricata: 

```sudo suricata -c /usr/local/etc/suricata/suricata.yaml -i eth0```

# Disable / enable / edit rules from database config.

You can now enable / disable rules, tune rules or delete / modify rules using sql statements. 

Some interesting commands you might consider:

```
describe signatures;

select count(*) from signatures where enabled = false;

select count(*) from signatures where enabled = true;

select enabled, header, sid, proto from signatures where raw like '%filestore%';

 # Then change all filestore rules to be enabled eg.

update signatures set enabled = true where raw like '%filestore%';

# Then update that particular rule to be a high priority:

update signatures set priority = 1 where raw like '%filestore%'; 

# Supress annoying startup errors such as modbus and dnp3 warnings: 

mysql> update signatures set enabled = false where raw like '%modbus%' or raw like '%dnp3%';
Query OK, 15 rows affected (0.22 sec)
Rows matched: 16  Changed: 15  Warnings: 0

```

etc. You can delete, insert or disable/enable rules this way.

# Reload rules from database table.

> sudo suricatasc -c reload-rules

# Django it. 

You can now build a django model around that table by telling it the database table name is "signatures"

eg

```

class SuricataRule(models.Model):

    raw = models.CharField(max_length=2500, null=False, default="")
    enabled = models.BooleanField(default=True)
    priority = models.IntegerField(null=True)
    #... THE REST OF THE FIELDS BUILT FROM SURICATA-UPDATE UTILITY
    
    class Meta:
        #unique_together = [['sid', 'rev']]
        constraints = [
            models.UniqueConstraint(fields=['sid'], name='Signature ID must be unique')
        ]
        db_table = "signatures" #here you can specify the special table name signatures for your django models. 


```







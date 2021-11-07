Cloning the repository:

> sudo git clone https://github.com/CosmoRied/suricata.git 

Change to this branch: 

> git checkout remotes/origin/mysql.

You have to configure, make and make install the program to compile and install this feature.

Get the dependencies for compilation: 

> sudo apt-get -y install libpcre3 libpcre3-dbg libpcre3-dev \
build-essential autoconf automake libtool libpcap-dev libnet1-dev \
libyaml-0-2 libyaml-dev zlib1g zlib1g-dev libcap-ng-dev libcap-ng0 \
make libmagic-dev libjansson-dev libjansson4 pkg-config

You can refer to the suricata documentation on how to compile here; https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Ubuntu_Installation & https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Suricata_Installation

You need to do a couple of things for this to succeed with the the MYSQL libraries:

Get the list of compiler flags and libraries you need for mysql to worl

> mysql_config --cflags --libs

It is:  

> -I/usr/include/mysql 

> -L/usr/lib/x86_64-linux-gnu -lmysqlclient -lpthread -lz -lm -lrt -lssl -lcrypto -ldl -lresolv

Now you need to include those options when you configure your system: In my case I used the command below. 

> sudo ./configure LIBS="-L/usr/lib/x86_64-linux-gnu -lmysqlclient -lpthread -lz -lm -lrt -lssl -lcrypto -ldl -lresolv" CFLAGS="-I/usr/include/mysql"

Fix any outstanding packages before completing the compilation. eg, cbindgen or libhtp...

> sudo apt-get install cbindgen

...

> sudo apt-get install rustc

...

When the configure command completes succesfully, only then can you make and make install...

> sudo make && sudo make install.

In /etc/suricata/suricata.yaml file, tell it that you want to have the path for rules files defalut path to 

>default-rule-path: /etc/suricata/
>
>rule-files:
>  - my.cnf

my.cnf file looks like this:

>[client]

>database = suricata

>user = db_username

>password = db_password

>default-character-set = utf8

Start suricata: 

> sudo suricata -c /etc/suricata/suricata.yaml -i eth0

If you haven't loaded rules into your database yet you can download and install the modified suricata-update utitilty and load rules using that.

# Load your database with rules...

You need the modified suricata update utilty that inserts rules into the database here: https://github.com/CosmoRied/suricata-update/tree/mysql

> sudo suricata-update --database --mysqlconf /etc/suricata/my.cnf

It creates a table called "signatures" in a database named in your my.cnf file. You need to create that database and grant permissions to the database user.

Once those rules are loaded into your database, have suricata reload the rules from there.

> sudo suricatasc -c reload-rules

# Django it. 

You can now build a django model around that table by telling it the database table name is "signatures"

eg

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
        db_table = "signatures"


Check a working prototype here: https://rule-sets.herokuapp.com/





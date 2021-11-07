This is a branch that enables you to load rules into a database table and have suricata read / reload those rules from the db. 

You need to download this repository and switch to the branch *mysql.

Do that by cloning the repository sudo git clone https://github.com/CosmoRied/suricata.git then changing to the branch. git checkout remotes/origin/mysql.

Now that you're in that branch, you have to configure, make and make install the program to compile and install this feature. 

Run,

> sudo sh autogen.sh

Don't forget that mysql support isn't supported by the suricata team, so you'll have to add a couple of lines in the ./configure option to get it to make properly.

Run this command on the command line to get the list of compiler flags and libraries you need to include in your configure options before make.

> mysql_config --cflags --libs

The output should look like this:

> -I/usr/include/mysql 

> -L/usr/lib/x86_64-linux-gnu -lmysqlclient -lpthread -lz -lm -lrt -lssl -lcrypto -ldl -lresolv

Now you can use those with your configure command to build inn mysql support.

eg.

> sudo ./configure LIBS="-L/usr/lib/x86_64-linux-gnu -lmysqlclient -lpthread -lz -lm -lrt -lssl -lcrypto -ldl -lresolv" CFLAGS="-I/usr/include/mysql"

Install the necessary packages required by suricata, eg. cbindgen or libhtp (I needed to add cbindgen using apt-get install cbindgen).

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





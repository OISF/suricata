Syslog Alerting Compatibility
=============================

Suricata can alert via syslog which is a very handy feature for central log collection, compliance, and reporting to a SIEM. Instructions on setting this up can be found in the .yaml file in the section where you can configure what type of alert (and other) logging you would like.

However, there are different syslog daemons and there can be parsing issues with the syslog format a SIEM expects and what syslog format Suricata sends. The syslog format from Suricata is dependent on the syslog daemon running on the Suricata sensor but often the format it sends is not the format the SIEM expects and cannot parse it properly.

Popular syslog daemons
----------------------

* **syslogd** - logs system messages
* **syslog-ng** - logs system messages but also supports TCP, TLS, and other enhanced enterprise features
* **rsyslogd** - logs system messages but also support TCP, TLS, multi-threading, and other enhanced features
* **klogd** - logs kernel messages
* **sysklogd** - basically a bundle of syslogd and klogd

If the syslog format the Suricata sensor is sending is not compatible with what your SIEM or syslog collector expects, you will need to fix this. You can do this on your SIEM if it is capable of being able to be configured to interpret the message, or by configuring the syslog daemon on the Suricata sensor itself to send in a format you SIEM can parse. The latter can be done by applying a template to your syslog config file.

Finding what syslog daemon you are using
----------------------------------------

There are many ways to find out what syslog daemon you are using but here is one way:

::


  cd /etc/init.d
  ls | grep syslog

You should see a file with the word syslog in it, e.g. "syslog", "rsyslogd", etc. Obviously if the name is "rsyslogd" you can be fairly confident you are running rsyslogd. If unsure or the filename is just "syslog", take a look at that file. For example, if it was "rsyslogd", run:

::


  less rsyslogd

At the top you should see a comment line that looks something like this:

::


  # rsyslog        Starts rsyslogd/rklogd.

Locate those files and look at them to give you clues as to what syslog daemon you are running. Also look in the *start()* section of the file you ran "less" on and see what binaries get started because that can give you clues as well.

Example
-------

Here is an example where the Suricata sensor is sending syslog messages in rsyslogd format but the SIEM is expecting and parsing them in a sysklogd format. In the syslog configuration file (usually in /etc with a filename like rsyslog.conf or syslog.conf), first add the template:

::


  $template sysklogd, "<%PRI%>%syslogtag:1:32%%msg:::sp-if-no-1st-sp%%msg%"

Then send it to the syslog server with the template applied:

::


  user.alert @10.8.75.24:514;sysklogd

Of course this is just one example and it will probably be different in your environment depending on what syslog daemons and SIEM you use but hopefully this will point you in the right direction.

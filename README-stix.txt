Updated Demo Notes

Set-Up

-          Retrieve our updated Suricata and Yeti code from github

-          Configure Suricata and Yeti using their current set up guides (installing any required dependencies).  In addition use pip to install the python package xmltodict.

 

Build and Configure

-          After installing all dependencies using Suricata and Yeti set up guides, do the following to build Suricata with the Unix Socket enabled and to set up our new rules file

-          cd <dir-to-src>/suricata

-          ./autogen.sh

-          ./configure --enable-unix-socket --with-libnspr-includes=/usr/include/nspr

-          Modify the suricata.yaml file you plan on starting Suricata up with:

     o   In the unix-command section, edit enabled to yes

     o   In the rule-files section add an entry for our new stix.rules file

     o   in the stream section edit checksum-validation, set it to no

-          make

 

Run

• Navigate to where the suricata executable is put as a result of make, i.e. <dir-to-src>/suricata/src/.libs

• Start-up Suricata:
∘ sudo ./suricata –c <dir-to-src>/suricata.yaml –i eth0 –l <dir-to-logs>/logs

• Under the yeti/scripts folder start up Yeti using the quickstart.sh script
∘ sudo <git>/yeti/scripts/quickstart.sh

•  Simulate having an SMTP server running if there isn't one already handy:
∘ sudo python -m smtpd -n -c DebuggingServer localhost:25

• Under the yeti folder there is an exampleSTIX folder where you will find the watchlist XML files we used for our own demo.  Use the inbox_client.py script to send these XML files to Yeti
∘ <some-dir>/yeti/scripts/inbox_client.py -–content-file <some-dir>/yeti/exampleSTIX/stix_watchlist.xml


 

Results

-          To view the results of this demo, navigate to the logs folder for Suricata (i.e. specified on the command line when starting up Suricata with the “-l” option)

-          Tail this log file

-          Generate traffic to an IP address listed in the Watchlist XML file that has been processed.  You should see output in the log file that indicates “STIX IP Watch List was matched” and the affected IP address.

-           to simulate SMTP traffic use a client like Thunderbird, you can easily make it simulate whatever kind of malicious traffic you need


My latest, favorite way to test is using Thunderbird configured to deliver via SMTP.

When I do my testing I run everything on the same machine.  Something I learned is that when using local loopback device or even a VirtualBox private network that packets often don't have checksums attached.  The default configuration in Suricata rejects packets with bad or missing checksums.  So you may see absolutely no traffic make its' way into the decoding or application layers. To get around this, find the stream section in suricata.yaml.  Under it is a setting: checksum-validation, set it to no.  By default it is set to yes.
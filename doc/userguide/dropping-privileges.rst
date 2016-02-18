Dropping Privileges After Startup
=================================

Currently, libcap-ng is needed for dropping privileges on Suricata
after startup. For libcap, see status of feature request number #276
-- Libcap support for dropping privileges.

Download the current version of libcap-ng from upstream, see also
http://people.redhat.com/sgrubb/libcap-ng/ChangeLog

::

  wget http://people.redhat.com/sgrubb/libcap-ng/libcap-ng-0.7.4.tar.gz
  tar -xzvf libcap-ng-0.7.4.tar.gz
  cd libcap-ng-0.7.4
  ./configure
  make
  make install

Download, configure, compile, and install Suricata for your particular
setup. See `Suricata Installation
<https://redmine.openinfosecfoundation.org/projects/suricata/wiki/Suricata_Installation>`_. Depending
on your environment, you may need to add the
--with-libpcap_ng-libraries and --with-libpcap_ng-includes options
during the configure step. e.g:

::

  ./configure --with-libcap_ng-libraries=/usr/local/lib \
    --with-libcap_ng-includes=/usr/local/include

Now, when you run Suricata, tell it what user and/or group you want it
to run as after startup with the --user and --group options.
e.g. (this assumes a 'suri' user and group):

::

  /usr/local/bin/suricata -c /etc/suricata/suricata.yaml \
    -D -i eth0 --user=suri --group=suri

You will also want to make sure your user/group permissions are set so
suricata can still write to its log files which are usually located in
/var/log/suricata.

::

  mkdir -p /var/log/suricata
  chown -R root:suri /var/log/suricata
  chmod -R 775 /var/log/suricata

If you rely on the pid files be aware that as of version 1.4.x
Suricata writes the pid file before it switches uids.  This means that
the pid file will be owned by root and will not be readable by the
alternative uid.  If this is an issue for you then a work around is to
set the sgid bit on the directory that the pid file will be created
in.  This will cause all files in this directory to inherit the gid
from the parent directory rather than the creating process.

::

  chmod g+s ~sensors/sensor1/run

  ls -ld ~sensors/sensor1/run
  drwxr-sr-x 2 sensors sensors 4096 Aug  9 09:20 ~sensors/sensor1/run

and so after running suricata we get

::

  ls -ld ~sensors/sensor1/run/suricata.pid
  -rw-r----- 1 root sensors 6 Aug  9 09:20 ~sensors/sensor1/run/suricata.pid

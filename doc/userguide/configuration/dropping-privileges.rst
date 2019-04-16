Dropping Privileges After Startup
=================================

Currently, dropping privileges can be either done via libcap-ng or with POSIX
seteuid()/setegid().

When the privilege drop is done by libcap-ng, the process real, effective and saved
user/group ID is set to the values provided by the user configuration.
Furthermore, process capabilities are set ensure that operations requiring
higher permissions can be performed properly.
Once done, the privilege level stays unchanged for the lifetime of the process.

When libcap-ng support is disabled, privilege drop is done via
seteuid()/setegid() on startup. Operations requiring higher permissions are
placed between the functions SCPrivsRaise()/SCPrivsDrop().

Between SCPrivsRaise() and SCPrivsDrop(), the process privileges are raised back
to the saved user/group level during the process runtime.

For libcap, see status of feature request number #276
-- Libcap support for dropping privileges.

Most distributions have ``libcap-ng`` in their repositories.

To download the current version of libcap-ng from upstream, see also
http://people.redhat.com/sgrubb/libcap-ng/ChangeLog

::

  wget http://people.redhat.com/sgrubb/libcap-ng/libcap-ng-0.7.8.tar.gz
  tar -xzvf libcap-ng-0.7.8.tar.gz
  cd libcap-ng-0.7.8
  ./configure
  make
  make install

Download, configure, compile and install Suricata for your particular setup.
See :doc:`../install`. Depending on your environment, you may need to add the
--with-libpcap_ng-libraries and --with-libpcap_ng-includes options
during the configure step. e.g:

::

  ./configure --with-libcap_ng-libraries=/usr/local/lib \
    --with-libcap_ng-includes=/usr/local/include

Now, when you run Suricata, tell it what user and/or group you want it
to run as after startup with the --user and --group options.
e.g. (this assumes a 'suri' user and group):

::

  suricata -D -i eth0 --user=suri --group=suri

You will also want to make sure your user/group permissions are set so
suricata can still write to its log files which are usually located in
/var/log/suricata.

::

  mkdir -p /var/log/suricata
  chown -R root:suri /var/log/suricata
  chmod -R 775 /var/log/suricata


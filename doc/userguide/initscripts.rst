Init Scripts
============

For Ubuntu with Upstart, the following can be used in ``/etc/init/suricata.conf``:


::


  # suricata
  description "Intrusion Detection System Daemon"
  start on runlevel [2345]
  stop on runlevel [!2345]
  expect fork
  exec suricata -D --pidfile /var/run/suricata.pid -c /etc/suricata/suricata.yaml -i eth1


For FreeBSD the following can be used in ``/usr/local/etc/rc.d/suricata``:


::

  #!/bin/sh
  
  # PROVIDE: suricata
  # REQUIRE: NETWORKING
  # KEYWORD: shutdown
  
  . /etc/rc.subr
  
  name=suricata
  rcvar=suricata_enable
  command=/usr/local/bin/${name}
  
  load_rc_config $name
  : ${suricata_enable:="NO"}
  : ${suricata_interface:="eth0"}
  
  command_args="-D -c /usr/local/etc/suricata/suricata.yaml -i $suricata_interface"
  
  run_rc_command "$1"


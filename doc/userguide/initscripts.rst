Init Scripts
============

For Ubuntu with Upstart, the following can be used in /etc/init/suricata.conf:


::


  # suricata
  description "Intruder Detection System Daemon"
  start on runlevel [2345]
  stop on runlevel [!2345]
  expect fork
  exec suricata -D --pidfile /var/run/suricata.pid -c /etc/suricata/suricata.yaml -i eth1

Endace DAG
==========

Suricata comes with native Endace DAG card support. This means Suricata can use the *libdag* interface directly, instead of a libpcap wrapper (which should also work).

Steps:

Configure with DAG support:


::


  ./configure --enable-dag --prefix=/usr --sysconfdir=/etc --localstatedir=/var
  make
  sudo make install

Results in:

::


  Suricata Configuration:
    AF_PACKET support:                       no
    PF_RING support:                         no
    NFQueue support:                         no
    IPFW support:                            no
    DAG enabled:                             yes
    Napatech enabled:                        no

Start with:


::


  suricata -c suricata.yaml --dag 0:0

Started up!


::


  [5570] 10/7/2012 -- 13:52:30 - (source-erf-dag.c:262) <Info> (ReceiveErfDagThreadInit) -- Attached and started stream: 0 on DAG: /dev/dag0
  [5570] 10/7/2012 -- 13:52:30 - (source-erf-dag.c:288) <Info> (ReceiveErfDagThreadInit) -- Starting processing packets from stream: 0 on DAG: /dev/dag0

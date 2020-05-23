Hassh Keywords
==============

Suricata comes with a Hassh integration (https://github.com/salesforce/hassh). Hassh is used to fingerprint ssh clients and servers.

Hassh must be enabled in the Suricata config file (set 'app-layer.protocols.ssh.hassh' to 'yes').

hassh
-----

Match on hassh (md5 of of hassh algorithms of client).

Example::
  alert ssh any any -> any any (msg:"match hassh"; \
      hassh; content:"ec7378c1a92f5a8dde7e8b7a1ddf33d1";\
      sid:1000010;)
      
``hassh`` is a 'sticky buffer'.

``hassh`` can be used as ``fast_pattern``.

hassh.string
------------

Match on Hassh string (hassh algorithms of client).

Example::
  alert ssh any any -> any any (msg:"match hassh-string"; \
      hassh.string; content:"none,zlib@openssh.com,zlib"; \
      sid:1000030;

``hassh.string`` is a 'sticky buffer'.

``hassh.string`` can be used as ``fast_pattern``.

hasshServer
-----------

Match on hassh (md5 of of hassh algorithms of server).

Example::

  alert ssh any any -> any any (msg:"match SSH hash-server"; \
      hasshServer; content:"b12d2871a1189eff20364cf5333619ee"; \
      sid:1000020;)

``hasshServer`` is a 'sticky buffer'.

``hasshServer`` can be used as ``fast_pattern``.

hasshServer.string
------------------

Match on hassh string (hassh algorithms of server).

Example::
  alert ssh any any -> any any (msg:"match SSH hash-server-string"; \
      hasshServer.string; content:"umac-64-etm@openssh.com,umac-128-etm@openssh.com"; \
      sid:1000040;)

``hasshServer.string`` is a 'sticky buffer'.

``hasshServer.string`` can be used as ``fast_pattern``.

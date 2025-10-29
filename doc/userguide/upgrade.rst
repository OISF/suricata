Upgrading
=========

General instructions
--------------------

Suricata can be upgraded by simply installing the new version to the same
locations as the already installed version. When installing from source,
this means passing the same ``--prefix``, ``--sysconfdir``,
``--localstatedir`` and ``--datadir`` options to ``configure``.

::

    $ suricata --build-info|grep -A 3 '\-\-prefix'
        --prefix                                 /usr
        --sysconfdir                             /etc
        --localstatedir                          /var
        --datarootdir                            /usr/share


Configuration Updates
~~~~~~~~~~~~~~~~~~~~~

New versions of Suricata will occasionally include updated config files:
``classification.config`` and ``reference.config``. Since the Suricata
installation will not overwrite these if they exist, they must be manually
updated. If there are no local modifications they can simply be overwritten
by the ones Suricata supplies.

Major updates include new features, new default settings and often also remove
features. This upgrade guide covers the changes that might have an impact of
migrating from an older version and keeping the config. We encourage you to
also check all the new features that have been added but are not covered by
this guide. Those features are either not enabled by default or require
dedicated new configuration.

Upgrading to 9.0.0
------------------

Logging Changes
~~~~~~~~~~~~~~~
- The format of IKEv1 proposal attributes has been changed to handle
  duplicate attribute types. See :ref:`IKE logging changes
  <9.0-ike-logging-changes>`

- Ethertype values (``ether.ether_type``) are now logged matching the network order value.
  E.g., previously, ``ether_type`` values were logged in host order;  an ethertype value of ``0xfbb7``
  (network order) was logged as `47099`` (``0xb7fb``). This ethertype value will be logged as ``64439``.

Other Changes
~~~~~~~~~~~~~
- ``engine-analysis`` output has been changed for keywords that now use the generic integers framework

  - icmp_id
  - tcp.ack
  - tcp.seq
  - tcp.window

Upgrading to 8.0.1
------------------

Major changes
~~~~~~~~~~~~~

- Various expected PPP packet types will no longer be marked as Unsupported Protocol
  when in a PPPOE packet.
- Added Cisco Discovery Protocol Control Protocol as a valid PPP packet.

Keyword changes
~~~~~~~~~~~~~~~
- Usage of multiple ``tls.cert_subject`` in a rule will print a warning
  as this keyword was not and is not implemented as a multi-buffer.

Upgrading 7.0 to 8.0
--------------------
.. note:: ``stats.whitelist`` has been renamed to ``stats.score`` in ``eve.json``

Major changes
~~~~~~~~~~~~~
- SIP parser has been updated to inspect traffic carried by TCP as well.
  SIP keywords can still match on their respective fields in addition
  to these improvements.
  Transactions are logged with the same schema regardless of which
  transport protocol is carrying the payload.
  Also, SIP protocol is detected using pattern matching and not only
  probing parser.
- ``SIP_PORTS`` variable has been introduced in suricata.yaml
- Application layer's ``sip`` counter has been split into ``sip_tcp`` and ``sip_udp``
  for the ``stats`` event.
- Stats counters that are 0 can now be hidden from EVE logs. Default behavior
  still logs those (see :ref:`EVE Output - Stats <eve-json-output-stats>` for configuration setting).
- SDP parser, logger and sticky buffers have been introduced.
  Due to SDP being encapsulated within other protocols, such as SIP, they cannot be directly enabled or disabled.
  Instead, both the SDP parser and logger depend on being invoked by another parser (or logger).
- ARP decoder and logger have been introduced.
  Since ARP can be quite verbose and produce many events, the logger is disabled by default.
- It is possible to see an increase of alerts, for the same rule-sets, if you
  use many stream/payload rules, due to Suricata triggering TCP stream
  reassembly earlier.
- New transform ``from_base64`` that base64 decodes a buffer and passes the
  decoded buffer. It's recommended that ``from_base64`` be used instead of ``base64_decode``
- Datasets of type String now include the length of the strings to determine if the memcap value is reached.
  This may lead to memcaps being hit for older setups that didn't take that into account.
  For more details, check https://redmine.openinfosecfoundation.org/issues/3910
- DNS logging has been modified to be more consistent across requests,
  responses and alerts. See :doc:`DNS Logging Changes for 8.0
  <upgrade/8.0-dns-logging-changes>`.
- PF_RING support has been moved to a plugin. See :doc:`PF_RING plugin
  <upgrade/8.0-pfring-plugin>`.
- LDAP parser and logger have been introduced.
- The following sticky buffers for matching SIP headers have been implemented:

  - sip.via
  - sip.from
  - sip.to
  - sip.content_type
  - sip.content_length

- Napatech support has been moved to a capture plugin. See :doc:`Napatech plugin
  <upgrade/8.0-napatech-plugin>`.
- Unknown requirements in the ``requires`` keyword will now be treated
  as unmet requirements, causing the rule to not be loaded. See
  :ref:`keyword_requires`.
- The configuration setting controlling stream checksum checks no longer affects
  checksum keyword validation. In Suricata 7.0, when ``stream.checksum-validation``
  was set to ``no``, the checksum keywords (e.g., ``ipv4-csum``, ``tcpv4-csum``, etc)
  will always consider it valid; e.g., ``tcpv4-csum: invalid`` will never match. In
  Suricata 8.0, ``stream.checksum-validation`` no longer affects the checksum rule keywords.
  E.g., ``ipv4-csum: valid`` will only match if the check sum is valid, even when engine
  checksum validations are disabled.
- Lua detection scripts (rules) now run in a sandboxed
  environment. See :ref:`lua-detection`. Lua rules are now also
  enabled by default.
- Lua output scripts have no default module search path, a search path
  will need to be set before external modules can be loaded. See the
  new default configuration file or :ref:`lua-output-yaml` for more
  details.
- If the configuration value ``ftp.memcap`` is invalid, Suricata will set it to ``0`` which means
  no limit will be placed. In previous Suricata  releases, Suricata would terminate execution. A
  warning message will be displayed `Invalid value <value> for ftp.memcap` when this occurs.
- The utility applications ``suricatasc`` and ``suricatactl`` have
  been rewritten in Rust. For most end-users this is a transparent
  change, however if you run these tools from the source directory,
  patch them or use them as Python modules your workflows may need to
  be adapted.
- Datasets now have a default max limit for hashsize of 65536. This is
  configurable via the ``datasets.limits`` options.
- For detect inspection recursion limits, if no value is provided, the default is
  now set to 3000.
- AF_PACKET now has better defaults:

  - AF_PACKET will now default to defrag off for inline mode with
    ``cluster_flow`` as its not recommended for inline use. However
    it can still be enabled with the ``defrag`` configuration
    parameter.
  - AF_PACKET will now default to tpacket-v3 for non-inline modes,
    it remains disabled for inline modes. To keep tpacket-v2 for
    non-inline modes, the existing ``tpacket-v3`` configuration
    parameter can be set to ``false``.
  - The AF_PACKET default block size for both TPACKET_V2 and
    TPACKET_V3 has been increased from 32k to 128k. This is to allow
    for full size defragmented packets. For TPACKET_V3 the existing
    ``block-size`` parameter can be used to change this back to the
    old default of 32768 if needed. For TPACKET_V2 a new
    configuration parameter has been added, ``v2-block-size`` which
    can be used to tune this value for TPACKET_V2. Due to the
    increased block size, memory usage has been increased, but
    should not be an issue in most cases.
- DPDK interface settings can now be configured automatically by setting 
  ``auto`` to ``mempool-size``, ``mempool-cache-size``, ``rx-descriptors``,
  ``tx-descriptors``. See :ref:`dpdk-automatic-interface-configuration`.
- DPDK interface mempools are now allocated per thread instead of per port. This
  change improves performance and should not be visible from the user
  configuration perspective.
- DPDK supports link state check, allowing Suricata to start only when the link
  is up. This is especially useful for Intel E810 (ice) NICs as they need 
  a few seconds before they are ready to receive packets. With this check
  disabled, Suricata reports as started but only begins processing packets
  after the previously mentioned interval. Other cards were not observed to have
  this issue. This feature is disabled by default.
  See :ref:`dpdk-link-state-change-timeout`.
- Encrypted traffic bypass has been decoupled from stream.bypass setting.
  This means that encrypted traffic can be bypassed while tracking/fully
  inspecting other traffic as well.
- Encrypted SSH traffic bypass is now independently controlled through
  ``app-layer.protocols.ssh.encryption-handling`` setting. The setting can either
  be ``bypass``, ``track-only`` or ``full``.
  To retain the previous behavior of encrypted traffic bypass
  combined with stream depth bypass, set
  ``app-layer.protocols.ssh.encryption-handling`` to ``bypass`` (while also
  setting ``app-layer.protocols.tls.encryption-handling`` to ``bypass`` and
  ``stream.bypass`` to ``true``).
- Spaces are accepted in HTTP1 URIs instead of in the protocol version. That is:
  `GET /a b HTTP/1.1` gets now URI as `/a b` and protocol as `HTTP/1.1` when
  it used to be URI as `/a` and protocol as `b HTTP/1.1`
- The configuration structure of ``threading.cpu-affinity`` has been changed
  from a list format to a dictionary format. Additionally, member properties of
  `*-cpu-set` nodes have been moved one level up.
  The support for list items such as `- worker-cpu-set`, `- management-cpu-set`,
  etc. is still supported.
  To convert to the new configuration format follow the example below or
  the description in :ref:`suricata-yaml-threading`.

  .. code-block:: diff

      threading:
        cpu-affinity:
    -     - worker-cpu-set:
    -         cpu: [0, 1]
    +     worker-cpu-set:
    +       cpu: [0, 1]
- All applayer protocols except FTP and HTTP now trigger inspection upon completion
  of a request/response in the respective direction. This means that earlier a
  content that matched just because it fell in the inspection chunk without wholly
  belonging to any one request/response may not match any longer.

Removals
~~~~~~~~
- The ssh keywords ``ssh.protoversion`` and ``ssh.softwareversion`` have been removed.
- The detect engine stats counters for non-mpm-prefiltered rules ``fnonmpm_list``
  and ``nonmpm_list`` were not in use since Suricata 8.0.0 and **were thus removed
  in 8.0.1.**

Deprecations
~~~~~~~~~~~~
- The ``http-log`` output is now deprecated and will be removed in Suricata 9.0.
- The ``tls-log`` output is now deprecated and will be removed in Suricata 9.0.
- The ``syslog`` output is now deprecated and will be removed in
  Suricata 9.0. Note that this is the standalone ``syslog`` output and
  does affect the ``eve`` outputs ability to send to syslog.
- The ``default`` option in ``app-layer.protocols.tls.encryption-handling`` is
  now deprecated and will be removed in Suricata 9.0. The ``track-only`` option
  should be used instead.

Keyword changes
~~~~~~~~~~~~~~~
- ``ja3.hash`` and ``ja3s.hash`` no longer accept contents with non hexadecimal
  characters, as they will never match.

Logging changes
~~~~~~~~~~~~~~~
- RFB security result is now consistently logged as ``security_result`` when it was
  sometimes logged with a dash instead of an underscore.
- Application layer metadata is logged with alerts by default **only for rules that
  use application layer keywords**. For other rules, the configuration parameter
  ``detect.guess-applayer-tx`` can be used to force the detect engine to guess a
  transaction, which is not guaranteed to be the one you expect. **In this case,
  the engine will NOT log any transaction metadata if there is more than one
  live transaction, to reduce the chances of logging unrelated data.** This may
  lead to what looks like a regression in behavior, but it is a considered choice.

Other Changes
~~~~~~~~~~~~~
- libhtp has been replaced with a rust version. This means libhtp is no longer built and linked as a shared library, and the libhtp dependency is now built directly into suricata.

Upgrading 6.0 to 7.0
--------------------

Major changes
~~~~~~~~~~~~~
- Upgrade of PCRE1 to PCRE2. See :ref:`pcre-update-v1-to-v2` for more details.
- IPS users: by default various new "exception policies" are set to DROP
  traffic. Please see :ref:`Exception Policies <exception policies>` for details
  on the settings and their scope. For trouble shooting, please check `My traffic gets
  blocked after upgrading to Suricata 7
  <https://forum.suricata.io/t/my-traffic-gets-blocked-after-upgrading-to-suricata-7>`_.
- New protocols enabled by default: bittorrent-dht, quic, http2.
- The telnet protocol is also enabled by default, but only for the ``app-layer``.

Security changes
~~~~~~~~~~~~~~~~
- suricata.yaml now prevents process creation by Suricata by default with `security.limit-noproc`.
  The suricata.yaml configuration file needs to be updated to enable this feature.
  For more info, see :ref:`suricata-yaml-config-hardening`.
- Absolute filenames and filenames containing parent directory
  traversal are no longer allowed by default for datasets when the
  filename is specified as part of a rule. See :ref:`Datasets Security
  <datasets_security>` and :ref:`Datasets File Locations
  <datasets_file_locations>` for more information.
- Lua rules are now disabled by default (change also introduced in 6.0.13), see :ref:`lua-detection`.

Removals
~~~~~~~~
- The libprelude output plugin has been removed.
- EVE DNS v1 logging support has been removed. If still using EVE DNS v1 logging, see the manual section on DNS logging configuration for the current configuration options: :ref:`DNS EVE Configuration <output-eve-dns>`

Logging changes
~~~~~~~~~~~~~~~
- IKEv2 Eve logging changed, the event_type has become ``ike`` which covers both protocol versions. The fields ``errors`` and ``notify`` have moved to
  ``ike.ikev2.errors`` and ``ike.ikev2.notify``.
- FTP DATA metadata for alerts are now logged in ``ftp_data`` instead of root.
- Alert ``xff`` field is now logged as ``alert.xff`` for alerts instead of at the root.
- Protocol values and their names are built into Suricata instead of using the system's ``/etc/protocols`` file. Some names and casing may have changed
  in the values ``proto`` in ``eve.json`` log entries and other logs containing protocol names and values.
  See https://redmine.openinfosecfoundation.org/issues/4267 for more information.
- Logging of additional HTTP headers configured through the EVE
  ``http.custom`` option will now be logged in the ``request_headers``
  and/or ``response_headers`` respectively instead of merged into the
  existing ``http`` object. In Suricata 6.0, a configuration like::

    http:
      custom: [Server]

  would result in a log entry like::

    "http": {
      "hostname": "suricata.io",
      "http_method": "GET",
      "protocol": "HTTP/1/1",
      "server": "nginx",
      ...
    }

  This merging of custom headers in the ``http`` object could result
  in custom headers overwriting standard fields in the ``http``
  object, or a response header overwriting request header.

  To prevent the possibility of fields being overwritten, **all**
  custom headers are now logged into the ``request_headers`` and
  ``response_headers`` arrays to avoid any chance of collision.  This
  also facilitates the logging of headers that may appear multiple
  times, with each occurrence being logged in future releases (see
  note below).

  While these arrays are not new in Suricata 7.0, they had previously
  been used exclusively for the ``dump-all-headers`` option.

  As of Suricata 7.0, the above configuration example will now be
  logged like::

    "http": {
      "hostname": "suricata.io",
      "http_method": "GET",
      "protocol": "HTTP/1/1",
      "response_headers": [
        { "name": "Server", "value": "nginx" }
      ]
    }

  Effectively making the ``custom`` option a subset of the
  ``dump-all-headers`` option.

  If you've been using the ``custom`` option, this may represent a
  breaking change. However, if you haven't used it, there will be no
  change in the output.

  .. note::

     Currently, if the same HTTP header is seen multiple times, the
     values are concatenated into a comma-separated value.

     For more information, refer to:
     https://redmine.openinfosecfoundation.org/issues/1275.

- Engine logging/output now uses separate defaults for ``console`` and ``file``, to provide a cleaner output on the console.

  Defaults are:

  * ``console``: ``%D: %S: %M``

  * ``file``: ``[%i - %m] %z %d: %S: %M``

  The ``console`` output also changes based on verbosity level.

Deprecations
~~~~~~~~~~~~
- Multiple "include" fields in the configuration file will now issue a
  warning and in Suricata 8.0 will not be supported. See
  :ref:`includes` for documentation on including multiple files.
- For AF-Packet, the `cluster_rollover` setting is no longer supported. Configuration settings using ``cluster_rollover``
  will cause a warning message and act as though `cluster_flow`` was specified. Please update your configuration settings.

Other changes
~~~~~~~~~~~~~
- Experimental keyword `http2.header` is removed. `http.header`, `http.request_header`, and `http.response_header` are to be used.
- NSS is no longer required. File hashing and JA3 can now be used without the NSS compile time dependency.
- If installing Suricata without the bundled Suricata-Update, the ``default-rule-path`` has been changed from ``/etc/suricata/rules`` to ``/var/lib/suricata/rules`` to be consistent with Suricata when installed with Suricata-Update.
- FTP has been updated with a maximum command request and response line length of 4096 bytes. To change the default see :ref:`suricata-yaml-configure-ftp`.
- SWF decompression in http has been disabled by default. To change the default see :ref:`suricata-yaml-configure-libhtp`. Users with configurations from previous releases may want to modify their config to match the new default.
  See https://redmine.openinfosecfoundation.org/issues/5632 for more information.
- The new option `livedev` is enabled by default with `use-for-tracking` being set to `true`. This should be disabled if multiple live devices are used to capture traffic from the same network.

Upgrading 5.0 to 6.0
--------------------
- SIP now enabled by default
- RDP now enabled by default
- ERSPAN Type I enabled by default.

Major changes
~~~~~~~~~~~~~
- New protocols enabled by default: mqtt, rfb
- SSH Client fingerprinting for SSH clients
- Conditional logging
- Initial HTTP/2 support
- DCERPC logging
- Improved EVE logging performance

Removals
~~~~~~~~
- File-store v1 has been removed. If using file extraction, the file-store configuration
  will need to be updated to version 2. See :ref:`filestore-update-v1-to-v2`.
- Individual Eve (JSON) loggers have been removed. For example,
  ``stats-json``, ``dns-json``, etc. Use multiple Eve logger instances
  if this behavior is still required. See :ref:`multiple-eve-instances`.
- Unified2 has been removed. See :ref:`unified2-removed`.

Performance
~~~~~~~~~~~
- In YAML files w/o a `flow-timeouts.tcp.closed` setting, the default went from 0 to 10 seconds.
  This may lead to higher than expected TCP memory use:
  https://redmine.openinfosecfoundation.org/issues/6552

Upgrading 4.1 to 5.0
--------------------

Major changes
~~~~~~~~~~~~~
- New protocols enabled by default: snmp (new config only)
- New protocols disabled by default: rdp, sip
- New defaults for protocols: nfs, smb, tftp, krb5 ntp are all enabled
  by default (new config only)
- VXLAN decoder enabled by default. To disable, set
  ``decoder.vxlan.enabled`` to ``false``.
- HTTP LZMA support enabled by default. To disable, set ``lzma-enabled``
  to ``false`` in each of the ``libhtp`` configurations in use.
- classification.config updated. ET 5.0 ruleset will use this.
- decoder event counters use 'decoder.event' as prefix now. This can
  be controlled using the ``stats.decoder-events-prefix`` setting.

Removals
~~~~~~~~
- ``dns-log``, the text dns log. Use EVE.dns instead.
- ``file-log``, the non-EVE JSON file log. Use EVE.files instead.
- ``drop-log``, the non-EVE JSON drop log.

See https://suricata.io/about/deprecation-policy/

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

Upgrading to 7.0.12
-------------------

- Various expected PPP packet types will no longer be marked as Unsupported Protocol
  when in a PPPOE packet.
- Added Cisco Discovery Protocol Control Protocol as a valid PPP packet.

Upgrading to 7.0.9
------------------
- The AF_PACKET default block size for both TPACKET_V2 and TPACKET_V3
  has been increased from 32k to 128k. This is to allow for full size
  defragmented packets. For TPACKET_V3 the existing ``block-size``
  parameter can be used to change this back to the old default of
  32768 if needed. For TPACKET_V2 a new configuration parameter has
  been added, ``v2-block-size`` which can be used to tune this value
  for TPACKET_V2. Due to the increased block size, memory usage has
  been increased, but should not be an issue in most cases.
- Datasets specifying a custom `hashsize` will now be limited to 262144 by default.
  Additionally, the cumulative hash sizes for all datasets in use should not exceed
  67108864. These settings can be changed with the following settings.

  .. code-block:: yaml

    datasets:
      # Limits for per rule dataset instances to avoid rules using too many
      # resources.
      # Note: in Suricata 8 the built-in default will be set to lower values.
      limits:
        # Max value for per dataset `hashsize` setting
        #single-hashsize: 262144
        # Max combined hashsize values for all datasets.
        #total-hashsizes: 67108864
- For detect inspection recursion limits, if no value is provided, the default is
  3000 now.

Upgrading to 7.0.8
------------------
- Unknown requirements in the ``requires`` keyword will now be treated
  as unsatisfied requirements, causing the rule to not be loaded. See
  :ref:`keyword_requires`. To opt out of this change and to ignore
  unknown requirements, effectively treating them as satisfied the
  ``ignore-unknown-requirements`` configuration option can be used.

  Command line example::

    --set ignore-unknown-requirements=true

  Or as a top-level configuration option in ``suricata.yaml``:

  .. code-block:: yaml

    default-rule-path: /var/lib/suricata/rules
    rule-files:
      - suricata.rules
    ignore-unknown-requirements: true

  .. note:: This option will only exist in Suricata 7.0.8 and future
            7.0 releases. It will not be provided in
            Suricata 8. Please fix any rules that depend on this
            behavior.
- Application layer metadata is logged with alerts by default **only for rules that
  use application layer keywords**. For other rules, the configuration parameter
  ``detect.guess-applayer-tx`` can be used to force the detect engine to guess a
  transaction, which is not guaranteed to be the one you expect. **In this case,
  the engine will NOT log any transaction metadata if there is more than one
  live transaction, to reduce the chances of logging unrelated data.** This may
  lead to what looks like a regression in behavior, but it is a considered choice.
- The configuration setting controlling stream checksum checks no longer affects
  checksum keyword validation. In previous Suricata versions, when ``stream.checksum-validation``
  was set to ``no``, the checksum keywords (e.g., ``ipv4-csum``, ``tcpv4-csum``, etc)
  will always consider it valid; e.g., ``tcpv4-csum: invalid`` will never match. Now,
  ``stream.checksum-validation`` no longer affects the checksum rule keywords.
  E.g., ``ipv4-csum: valid`` will only match if the check sum is valid, even when engine
  checksum validations are disabled.

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
- Support for JA4 has been added. JA4 hashes will be computed when explicitly enabled or a rule uses
  `ja4.hash`. JA4 hashes are output under a restricted set of conditions (see below):

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

-  JA4 hashes are output under a restricted set of conditions when JA4 is dynamically or explicitly enabled:

   - Alerts: The signature causing the alert contains the `ja4.hash` keyword
   - Logs: With QUIC logs iff outputs.quic.ja4 is enabled (default off)
   - Logs: With TLS logs iff outputs.tls.ja4 is enabled (default off)

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

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

Major updates include new features, new default settings and often also
remove features.

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

See https://suricata.io/our-story/deprecation-policy/

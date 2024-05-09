
Verifying Source Tarball
========================

Once the Suricata release tarball has been downloaded, the PGP signature should
be verified. This can be done using the GPG application and is usually
available on Linux/BSD systems without having to manually install any
additional packages. For Mac or Windows systems installation packages can be
found at `<https://gnupg.org/>`_.

Verification Steps
------------------

These verification steps are for general guidance, the exact process and
commands may vary between operating systems.

Downloading the sig File
~~~~~~~~~~~~~~~~~~~~~~~~

The sig file needs to be downloaded as well as the tarball. Both files can be
found at `<https://suricata.io/download/>`_.

Importing the OISF Signing Key
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Once both the sig file and suricata tarball files are obtained, the OISF
signing key should be imported to the local gpg keyring. This can be done by
running the following command::

  $ gpg --receive-keys 2BA9C98CCDF1E93A

The above command should produce output similar to the following::

  gpg: key 2BA9C98CCDF1E93A: public key "Open Information Security Foundation
  (OISF) <releases@openinfosecfoundation.org>" imported
  gpg: Total number processed: 1
  gpg:               imported: 1

Verifying the Suricata Tarball
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To verify the contents of the Suricata tarball the following command should be
ran::

  $ gpg --verify suricata-7.0.5.tar.gz.sig suricata-7.0.5.tar.gz

Depending on the trust level assigned to the OISF signing keys, something
similar to the following output should be seen::

  $ gpg --verify suricata-7.0.5.tar.gz.sig suricata-7.0.5.tar.gz
  gpg: Signature made Tue 23 Apr 2024 11:58:56 AM UTC
  gpg:                using RSA key B36FDAF2607E10E8FFA89E5E2BA9C98CCDF1E93A
  gpg: checking the trustdb
  gpg: marginals needed: 3  completes needed: 1  trust model: pgp
  gpg: depth: 0  valid:   1  signed:   0  trust: 0-, 0q, 0n, 0m, 0f, 1u
  gpg: next trustdb check due at 2025-08-06
  gpg: Good signature from "Open Information Security Foundation (OISF)
  <releases@openinfosecfoundation.org>" [ultimate]

This indicates a valid signature and that the signing key is trusted.

.. note:: If output from the `--verify` command is similar to the following::

    gpg: Signature made Tue 23 Apr 2024 11:58:56 AM UTC
    gpg:                using RSA key B36FDAF2607E10E8FFA89E5E2BA9C98CCDF1E93A
    gpg: Can't check signature: No public key

  This indicates that the OISF signing key was not imported to the local GPG
  keyring.

.. note:: If output from the `--verify` command is similar to the following::

    gpg: Signature made Tue 23 Apr 2024 11:58:56 AM UTC
    gpg:                using RSA key B36FDAF2607E10E8FFA89E5E2BA9C98CCDF1E93A
    gpg: Good signature from "Open Information Security Foundation (OISF)
    <releases@openinfosecfoundation.org>" [unknown]
    gpg: WARNING: This key is not certified with a trusted signature!
    gpg:          There is no indication that the signature belongs to the owner.
    Primary key fingerprint: B36F DAF2 607E 10E8 FFA8  9E5E 2BA9 C98C CDF1 E93A

  This indicates that the OISF signing key was imported and the signatures are
  valid, but either the keys have been marked as trusted OR the keys are
  possibly a forgery.
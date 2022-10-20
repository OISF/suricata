Installation from GIT
=====================

Ubuntu Installation from GIT
----------------------------

This document will explain how to install and use the most recent code of
Suricata on Ubuntu. Installing from GIT on other operating systems is
basically the same, except that some commands are Ubuntu-specific
(like sudo and apt-get). In case you are using another operating system,
you should replace those commands with your OS-specific commands.

Pre-installation requirements
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Before you can build Suricata for your system, run the following command
to ensure that you have everything you need for the installation.

.. code-block:: bash

  sudo apt-get -y install libpcre3 libpcre3-dbg libpcre2-dev libpcre3-dev \
  build-essential autoconf automake libtool libpcap-dev libnet1-dev \
  libyaml-0-2 libyaml-dev pkg-config zlib1g zlib1g-dev libcap-ng-dev \
  libcap-ng0 make libmagic-dev libjansson-dev rustc cargo jq git-core

Add ``${HOME}/.cargo/bin`` to your path:

.. code-block:: bash

  export PATH=$PATH:${HOME}/.cargo/bin
  cargo install --force cbindgen

Depending on the current status of your system, it may take a while to
complete this process.

**IPS**

By default, Suricata works as an IDS. If you want to use it as an IDS and IPS
program, enter:

.. code-block:: bash

  sudo apt-get -y install libnetfilter-queue-dev libnetfilter-queue1 \
  libnfnetlink-dev libnfnetlink0

Suricata
~~~~~~~~

First, it is convenient to create a directory for Suricata.
Name it 'suricata' or 'oisf', for example. Open the terminal and enter:

.. code-block:: bash

  mkdir suricata  # mkdir oisf

Followed by:

.. code-block:: bash

  cd suricata  # cd oisf

Next, enter the following line in the terminal:

.. code-block:: bash

  git clone https://github.com/OISF/suricata.git
  cd suricata

Libhtp is not bundled. Get libhtp by doing:

.. code-block:: bash

  ./scripts/bundle.sh libhtp

Followed by:

.. code-block:: bash

  ./autogen.sh


To configure, please enter:

.. code-block:: bash

  ./configure


To compile, please enter:

.. code-block:: bash

  make

To install Suricata, enter:

.. code-block:: bash

  sudo make install
  sudo ldconfig

To install suricata-update

Follow the instructions found in
https://suricata-update.readthedocs.io/en/latest/quickstart.html

.. note:: If you would like to build ``suricata-update`` from source, enter:

  .. code-block:: bash

    sudo apt install -y python3 python3-distutils python3-yaml
    ./scripts/bundle.sh suricata-update
    cd suricata-update
    python3 setup.py build
    sudo python3 setup.py install
    sudo suricata-update

Auto-setup
~~~~~~~~~~

You can also use the available auto-setup features of Suricata. Ex:

.. code-block:: bash

  ./configure && make && sudo make install-conf

*make install-conf*
would do the regular "make install" and then it would automatically
create/setup all the necessary directories and ``suricata.yaml`` for you.

.. code-block:: bash

  ./configure && make && make install-rules

*make install-rules*
would do the regular "make install" and then it would automatically download
and set-up the latest ruleset from Emerging Threats available for Suricata.

.. code-block:: bash

  ./configure && make && make install-full

*make install-full*
would combine everything mentioned above (install-conf and install-rules) -
and will present you with a ready to run (configured and set-up) Suricata.

Post installation
~~~~~~~~~~~~~~~~~

Please continue with :ref:`Basic setup`.

In case you have already created your Suricata directory and cloned the
repository in it, if you want to update your local repository with the
most recent code, please run:

.. code-block:: bash

  cd suricata/suricata

next, enter:

.. code-block:: bash

  git pull

After that, you should run *./autogen.sh* again.

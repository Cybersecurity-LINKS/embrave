Quick Start
===========

Requirements
------------
The following dependencies must be installed:

    .. code-block:: bash

        $ sudo apt-get install git make cmake gcc libssl-dev openssl

Attester Requirements
---------------------
The following dependencies must be installed specific for the Attester application.

TPM2 Software Stack (TSS):
    .. code-block:: bash

        $ git clone -n https://github.com/tpm2-software/tpm2-tss
        $ git checkout 40485d368dbd8ad92c8c062ba38cd7eaa4489472
        $ ./bootstrap
        $ sudo ./configure --prefix=/usr
        $ sudo make -j$(nproc)
        $ sudo make install
        $ sudo ldconfig

TPM2 Access Broker & Resource Manager: 
    .. code-block:: bash

        $ git clone -n https://github.com/tpm2-software/tpm2-abrmd
        $ git checkout b2b0795796ef5588155bf43919dd4d7bf73c3a01
        $ ./bootstrap
        $ ./configure --with-dbuspolicydir=/etc/dbus-1/system.d \ 
        --with-systemdsystemunitdir=/usr/lib/systemd/system \
        --libdir=/usr/lib --prefix=/usr
        $ sudo make -j$(nproc)
        $ sudo make install
        $ sudo udevadm control --reload-rules && sudo udevadm trigger
        $ sudo systemctl daemon-reload

Dependencies of tpm2-tools:
    Install the dependencies listed at this `link <https://tpm2-tools.readthedocs.io/en/latest/INSTALL/>`_


Get Source Code
---------------

Get the main repo:

    .. code-block:: bash
        
        $ git clone https://github.com/Cybersecurity-LINKS/lemon.git

Get the submodules:

    .. code-block:: bash

        $ cd lemon
        $ git submodule update --init --recursive
        $ cd lib/tpm2-tools
        $ git checkout 4998ecfea817cd0efdd47bdf11a02dedab51c723

Build
-----

Build all components:

    .. code-block:: bash

        $ mkdir build
        $ cd build
        $ cmake ..
        $ make

The ``make`` command will build all the binaries. If the intention is to build only a specific compoents the targets defined are:

- ``attester-server``: The Attester component
- ``verifier``: The Verifier component
- ``join-service``: The Join Service component

To build a specific component, the following command can be used:

    .. code-block:: bash

        $ make <target-name>
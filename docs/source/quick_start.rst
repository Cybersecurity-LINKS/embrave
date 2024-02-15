Quick Start
===========

Requirements
------------

Attester Requirements
---------------------
The following dependencies must be installed before installing the application.

- TPM2 Software Stack (TSS)
    | ``$ git clone -n https://github.com/tpm2-software/tpm2-tss``
    | ``$ git checkout 40485d368dbd8ad92c8c062ba38cd7eaa4489472``
    | ``$ ./bootstrap``
    | ``$ sudo ./configure --prefix=/usr``
    | ``$ sudo make -j8``
    | ``$ sudo make install``
    | ``$ sudo ldconfig``

- TPM2 Access Broker & Resource Manager
    | ``$ git clone -n https://github.com/tpm2-software/tpm2-abrmd``
    | ``$ git checkout b2b0795796ef5588155bf43919dd4d7bf73c3a01``
    | ``$ ./bootstrap``
    | ``$ ./configure --with-dbuspolicydir=/etc/dbus-1/system.d --with-systemdsystemunitdir=/usr/lib/systemd/system --libdir=/usr/lib --prefix=/usr``
    | ``$ sudo make -j$(nproc)``
    | ``$ sudo make install``
    | ``$ sudo udevadm control --reload-rules && sudo udevadm trigger``
    | ``$ sudo systemctl daemon-reload``

- Dependencies of tpm2-tools
    Install the dependencies listed at this `link <https://tpm2-tools.readthedocs.io/en/latest/INSTALL/>`_


Installation
------------
- Install the required packages:
    ``$ sudo apt-get install git``
- Download the source code from the main repository:
    ``$ git clone https://github.com/Cybersecurity-LINKS/lemon.git``
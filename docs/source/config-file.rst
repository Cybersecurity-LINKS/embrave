Configuration File
==================

The system supports configuration through a a file, located in ``/etc/lemon.conf``. The file is in the format of a standard INI file, with sections and key-value pairs. The following sections are supported:

Sections
========

The ``lemon.conf`` file is divided into several sections, each used by a specific component.

AttesterAgent
-------------

The ``[AttesterAgent]`` section contains general settings for Attester.

.. code-block:: ini

    [AttesterAgent]

    # UUID
    uuid = 12345678-1234-1234-1234-123456789012

    # Port where it runs the http server
    port = 80

    # Port where is runs the https (TLS enabled) server
    tls_port = 443

    # Ip address on which make the binding
    ip = 127.0.0.1

    # Certificate and key for TLS paths
    tls_cert = /var/lemon/attester/tls/cert.crt
    tls_key = /var/lemon/attester/tls/key.pem

    # Path where store the EK certificates
    ek_rsa_cert = /var/lemon/attester/ek_rsa_cert.pem
    ek_ecc_cert = /var/lemon/attester/ek_ecc_cert.pem

    # Path where store the AK info
    ak_pub = /var/lemon/attester/ak_pub.pem
    ak_name = /var/lemon/attester/ak.name
    ak_ctx = /var/lemon/attester/ak.ctx
    ak_cert = /var/lemon/attester/ak.crt

    # Join Service IP address
    join_service_ip = localhost

    # Port where it runs the http Join Service server
    join_service_port = 8000


Verifier
--------

The ``[Verifier]`` section contains settings related to the Verifier.

.. code-block:: ini

    [Verifier]

    # Port where it runs the http server
    port = 80

    # Port where is runs the https (TLS enabled) server
    tls_port = 443

    # Ip address on which make the binding
    ip = 127.0.0.1

    # Flag to spacify if the server will run on TLS
    # or not (1 = TLS, 0 = NO TLS). NOT used yet!
    use_tls = 1

    # Certificate and key for TLS paths
    tls_cert_ca = /var/lemon/verifier/tls/ca.crt
    tls_cert = /var/lemon/verifier/tls/cert.crt
    tls_key = /var/lemon/verifier/tls/key.pem

    # Path of the verfier database (sqlite)
    db = file:/var/lemon/verifier/db.sqlite

    # Join Service IP address
    join_service_ip = localhost

    # Port where it runs the http Join Service server
    join_service_port = 8000

JoinService
-----------

The ``[JoinService]`` section contains settings related to the Join Service.

.. code-block:: ini

    [JoinService]

    # Port where it runs the http server
    port = 8000

    # Port where is runs the https (TLS enabled) server
    tls_port = 443

    # Ip address on which make the binding
    ip = localhost

    # Flag to spacify if the server will run on TLS
    # or not (1 = TLS, 0 = NO TLS). NOT used yet!
    use_tls = 1

    # Certificate and key for TLS paths
    tls_cert_ca = /var/lemon/join_servicetls/ca.crt
    tls_cert = /var/lemon/join_service/tls/cert.crt
    tls_key = /var/lemon/join_service/tls/key.pem

    # Path of the verfier database (sqlite)
    db = file:/var/lemon/join_service/db.sqlite

    # Path of ca hash certificates
    ca_x509_path = /home/linux/Documents/lemon/tpm_ca_certs_hash_dir
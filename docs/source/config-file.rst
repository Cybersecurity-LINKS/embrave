Configuration File
==================

The system supports configuration through a a file, located in ``/etc/embrave.conf``. The file is in the format of a standard INI file, with sections and key-value pairs. The following sections are supported:

Sections
--------

The ``embrave.conf`` file is divided into several sections, each used by a specific component.

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
    tls_cert = /var/embrave/attester/tls/cert.crt
    tls_key = /var/embrave/attester/tls/key.pem

    # Path where store the EK certificates
    ek_rsa_cert = /var/embrave/attester/ek_rsa_cert.pem
    ek_ecc_cert = /var/embrave/attester/ek_ecc_cert.pem

    # Path where store the AK info
    ak_pub = /var/embrave/attester/ak_pub.pem
    ak_name = /var/embrave/attester/ak.name
    ak_ctx = /var/embrave/attester/ak.ctx
    ak_cert = /var/embrave/attester/ak.crt

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
    tls_cert_ca = /var/embrave/verifier/tls/ca.crt
    tls_cert = /var/embrave/verifier/tls/cert.crt
    tls_key = /var/embrave/verifier/tls/key.pem

    # Path of the verfier database (sqlite)
    db = file:/var/embrave/verifier/db.sqlite

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
    tls_cert_ca = /var/embrave/join_servicetls/ca.crt
    tls_cert = /var/embrave/join_service/tls/cert.crt
    tls_key = /var/embrave/join_service/tls/key.pem

    # Path of the verfier database (sqlite)
    db = file:/var/embrave/join_service/db.sqlite

    # Path of ca hash certificates
    ca_x509_path = /home/linux/Documents/embrave/tpm_ca_certs_hash_dir
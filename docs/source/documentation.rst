Documentation
=============

Requirements
------------
.. code-block:: bash

    $ sudo apt-get install python3 python3-venv

Build Documentation
-------------------

To build the documentation move to the ``docs`` directory.
The documentation is built using Sphinx. To build the documentation, you need to install the required packages.

Install requirements with Python Virtual Environment:
    .. code-block:: bash

        $ python3 -m venv .venv
        $ source .venv/bin/activate
        (.venv) $ pip3 install -r requirements.txt

Check installation:
    .. code-block:: bash

        (.venv) $ sphinx-build --version
        sphinx-build 7.2.6


Build docs:
    .. code-block:: bash

        (.venv) $ make html

    The docs will be available in the ``build`` directory
    Open in browser the file ``index.html``.
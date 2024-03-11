# Build and Install
## Requirements
The following dependencies must be installed:
```sh
sudo apt-get install git make cmake gcc libssl-dev openssl
```
and a preferred MQTT broker E.g Mosquitto
```sh
sudo apt install mosquitto
```
## Attester Requirements
The following dependencies must be installed specific for the Attester application.

**TPM2 Software Stack (TSS):**
Install the required packages
```sh
sudo apt -y install \
  autoconf-archive \
  libcmocka0 \
  libcmocka-dev \
  procps \
  iproute2 \
  build-essential \
  git \
  pkg-config \
  gcc \
  libtool \
  automake \
  libssl-dev \
  uthash-dev \
  autoconf \
  doxygen \
  libjson-c-dev \
  libini-config-dev \
  libcurl4-openssl-dev \
  uuid-dev \
  libltdl-dev \
  libusb-1.0-0-dev \
  libftdi-dev
```
Install tpm2-tss software
```sh
git clone -n https://github.com/tpm2-software/tpm2-tss
git checkout 40485d368dbd8ad92c8c062ba38cd7eaa4489472
./bootstrap
sudo ./configure --prefix=/usr
sudo make -j8
sudo make install
sudo ldconfig
```
**TPM2 Access Broker & Resource Manager:**

```sh
git clone -n https://github.com/tpm2-software/tpm2-abrmd
git checkout b2b0795796ef5588155bf43919dd4d7bf73c3a01
./bootstrap
./configure --with-dbuspolicydir=/etc/dbus-1/system.d --with-systemdsystemunitdir=/usr/lib/systemd/system --libdir=/usr/lib --prefix=/usr
sudo make -j$(nproc)
sudo make install
sudo udevadm control --reload-rules && sudo udevadm trigger
sudo systemctl daemon-reload
```
**Dependencies of tpm2-tools:**
install the dependencies listed at this [link](https://tpm2-tools.readthedocs.io/en/latest/INSTALL/)

## Installation

```sh
git clone https://github.com/Cybersecurity-LINKS/embrave
cd embrave
git submodule update --init --recursive
cd lib/tpm2-tools
git checkout 4998ecfea817cd0efdd47bdf11a02dedab51c723
cd ../../
mkdir build
cd build
cmake ..
sudo make 
```
The ``sudo make`` command will build all the binaries. If the intention is to build only a specific compoents, the command is ``sudo make <target-name>`` with targets defined as:

- ``attester-server``: The Attester component
- ``verifier``: The Verifier component
- ``join-service``: The Join Service component






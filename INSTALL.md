Dependencies
TSS
    git clone -n https://github.com/tpm2-software/tpm2-tss
    git checkout 40485d368dbd8ad92c8c062ba38cd7eaa4489472
    sudo ./configure --prefix=/usr
    sudo make -j8
    sudo make install
    sudo ldconfig
tpm abrmd
    git clone -n https://github.com/tpm2-software/tpm2-abrmd
    git checkout b2b0795796ef5588155bf43919dd4d7bf73c3a01
    ./configure --with-dbuspolicydir=/etc/dbus-1/system.d --with-systemdsystemunitdir=/usr/lib/systemd/system --libdir=/usr/lib --prefix=/usr
    sudo make -j8
    sudo make install
    sudo udevadm control --reload-rules && sudo udevadm trigger
    sudo systemctl daemon-reload

tpm tools depdencies
sqlite3
sudo apt install libsqlite3-dev
1 tpm2 tools
    ./bootstrap
    ./configure
2 tpa && RA

# compile TPA
./TPA_build.sh tcp://listen_ip_no_tls:port tcp://listen_ip_tls:port
# example
~/tpa $ ./TPA_build.sh tcp://192.168.1.12:8765 tcp://localhost:8766

# compile RA (0 IP no TLS 1 IP TLS)
./RA_build.sh listen_ip_no_tls:port int_tls(0,1)
# example
~/tpa $ ./RA_build.sh 192.168.1.12 1




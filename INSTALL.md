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




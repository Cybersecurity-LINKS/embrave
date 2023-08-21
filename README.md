# TPA

create_whitelist.py
sudo python3 Whitelist_generator/add_whitelist.py <path/file_to_exclude>

# creation of certficate usage
~/tpa $ ./script/create_certificates.sh

# compile TPA
./TPA_build.sh tcp://listen_ip_no_tls:port tcp://listen_ip_tls:port
# example
~/tpa $ ./TPA_build.sh tcp://192.168.1.12:8765 tcp://localhost:8766
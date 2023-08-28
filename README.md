# Trusted Platform Agent (TPA) and Remote Attestor (RA)


[INSTALL](INSTALL.md)

create_whitelist.py
sudo python3 script/add_excludelist.py <path/file_to_exclude>

# creation of certficate usage
~/tpa $ ./script/create_certificates.sh

# compile TPA
./TPA_build.sh tcp://listen_ip_no_tls:port tcp://listen_ip_tls:port
# example
~/tpa $ ./TPA_build.sh tcp://192.168.1.12:8765 tcp://localhost:8766

# compile RA (0 IP no TLS 1 IP TLS)
./RA_build.sh listen_ip_no_tls:port int_tls(0,1)
# example
~/tpa $ ./RA_build.sh 192.168.1.12 1

# to add files or paths to the whitelist, simply add them to the whitelist.txt file and then create the golden value database
# golden value database
 sudo python3 ./script/goldenvalue_db_generator.py sha256 /

scp pi@192.168.1.12:/home/pi/tpa/Protocols/Explicit/goldenvalues.db ./Protocols/Explicit/
scp pi@192.168.1.12:/home/pi/tpa/Server/certs/ca.crt ./Server/certs/
scp pi@192.168.1.12:/home/pi/tpa/Server/certs/server.crt ./Server/certs/
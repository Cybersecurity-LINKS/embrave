# Trusted Platform Agent (TPA) and Remote Attestor (RA) (name TBD)

## Build and install
Refer to the [INSTALL.md](INSTALL.md) file for instructions about building and installing the applications.

## Provisioning
### TPM keys
First run this script on the tpa to generate the TPM keys
```sh
./script/create_tpm_keys.sh
```
### Public certificate for TLS
Run this script on the tpa to generate the keys for the TLS connection
```sh
./script/create_certificates.sh
```
### Golden values database and the exclude list database
Add all files or paths, to be excluded during the verification of the IMA Log, one per line in the file ./script/exclude.txt. Then run this Python script on the tpa. It will take some time.

```
sudo python3 ./script/goldenvalue_db_generator.py sha256 /
```
If you subsequently need to add other files/paths to the exclude list, you can use the following Python script
```
sudo python3 ./script/add_excludelist.py <path/file_to_exclude>
```

### Remote Attestor Preparation
Run the following script on the RA
```
TODO script
scp pi@192.168.1.12:/home/pi/tpa/Protocols/Explicit/goldenvalues.db ./Protocols/Explicit/
scp pi@192.168.1.12:/home/pi/tpa/Server/certs/ca.crt ./Server/certs/
scp pi@192.168.1.12:/home/pi/tpa/Server/certs/server.crt ./Server/certs/

```
## Execution 
### TPA
Run the following script on the TPA passing as input parameter tcp://listen_ip_no_tls:port tcp://listen_ip_tls:port. Example:
```sh
./TPA_build.sh tcp://192.168.1.12:8765 tcp://localhost:8766
```
### RA
Run the following script on the RA passing as input parameter the IP address of the tpa to attest and 1 for TLS connection or 0 without TLS connection
```sh
./RA_run.sh 192.168.1.12 1
```
## License
TBD

## Copyright
TBD
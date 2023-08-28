# Trusted Platform Agent (TPA) and Remote Attestor (RA) (name TBD)

## Build and install
Refer to the [INSTALL.md](INSTALL.md) file for instructions about building and installing the applicantions.

## Provisioning
### creation of TPM keys
First run this script on the tpa to generate the tpm keys
```sh
./script/create_tpm_keys.sh
```
### creation of public certficate for TLS
run this script on the tpa to generate the keys for TLS connection
```sh
./script/create_certificates.sh
```
### creation of the goldenvalues database and the excludelist database
Add all files or paths, to be excluded dduring the verification of the IMA Log, one per line in the file ./script/exclude.txt. Then run this python script on the tpa. It will take some time.

```
sudo python3 ./script/goldenvalue_db_generator.py sha256 /
```
If you subsequently need to add other files/paths to the exclude list, you can use the following script
```
sudo python3 ./script/add_excludelist.py <path/file_to_exclude>
```






scp pi@192.168.1.12:/home/pi/tpa/Protocols/Explicit/goldenvalues.db ./Protocols/Explicit/
scp pi@192.168.1.12:/home/pi/tpa/Server/certs/ca.crt ./Server/certs/
scp pi@192.168.1.12:/home/pi/tpa/Server/certs/server.crt ./Server/certs/

## License
TBD

## Copyright
TBD
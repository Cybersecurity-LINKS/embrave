# Lemon
C-language implementation of a Trusted Platform Agent (TPA) and Remote Attestor (RA) for a Lightweight Remote Attestation. The TPA waits on two TCP sockets (one of which is configured for a TLS connection) for the challenge of an RA and sends:
* The TPM Quote and signature calculated with the nonce and the digest of SHA1 PCR10 and all SHA256 PCRs
* The SHA1 PCR10 an all SHA256 PCRs
* The complete IMA Log
* In the case of TLS connection, PCR9 SHA256 is extended with the SHA256 digest of the server TLS public certificate

The RA verifies:
* The TPM Quote against the quoted data and the public AK key (in his possession)
* The quoted digest of PCR against the digest of sent PCRs
* All IMA log events against the golden Values database or the Exclude database
* Reconstruction of SHA1 PCR10 and SHA256 PCR and comparison against the sent ones
* In the case of TLS connection, the PCR9 SHA256 extension is re-created with the server TLS public certificate (in his possession) and compared with the sent PCR9

Limitation:
- Only ima-ng format of IMA log is supported
- In the event of a server key change, the device must be restarted
- Some files must be excluded manually
- Exclusive support of TPM2.0

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
### RA entry freshness 
to change the maximum validity time of the RA database entry, compile the client by adding the parameter -DFRESH=<time max in seconds> Default: 60s

## License
TBD

## Copyright
TBD

# Embrave
C-language implementation of a Remote Attestation Framework. Implements an Agent, a Verifier, and a Join service to register agents and Verifiers.



The TPA waits on two TCP sockets (one of which is configured for a TLS connection) for the challenge of an RA and sends:
* The TPM Quote and signature calculated with the nonce and the digest of SHA1 PCR10 and all SHA256 PCRs
* The SHA1 PCR10 an all SHA256 PCRs
* The complete IMA Log
* In the case of TLS connection, PCR9 SHA256 is extended with the SHA256 digest of the server TLS public certificate

The Remote Attestor verifies:
* The TPM Quote against the quoted data and the public AK key (in his possession)
* The quoted digest of PCR against the digest of sent PCRs
* All IMA log events against the Golden Values database or the Exclude database
* Reconstruction of SHA1 PCR10 and SHA256 PCR and comparison against the sent ones

Limitation:
- Only ima-ng format of IMA log is supported at the moment
- Some files must be excluded manually
- Exclusive support of TPM2.0

## Build and install
Refer to the [INSTALL.md](INSTALL.md) file for instructions about building and installing the applications.

## Provisioning
### Golden values database and the exclude list database
Add all files or paths, to be excluded during the verification of the IMA Log, one per line in the file ./script/exclude.txt. Then run this Python script on the tpa. It will take some time.

```
sudo python3 ./script/goldenvalue_db_generator.py sha256 /
```
If you subsequently need to add other files/paths to the exclude list, you can use the following Python script
```
sudo python3 ./script/add_excludelist.py <path/file_to_exclude>
```

### Config file





### Remote Attestor Preparation
Run the following script on the RA
```


```
## Execution
### Join Service



### Agent
Run the following script on the TPA passing as input parameter tcp://listen_ip_no_tls:port tcp://listen_ip_tls:port. Example:
```sh
sudo ./agent.build/attester_server tcp://192.168.1.12:8765 tcp://192.168.1.12:8766
```
### Verifier
Run the following script on the RA passing as input parameter the IP address of the tpa to attest and 1 for TLS connection or 0 without TLS connection and an integer that rapresents the row of the tpa to attest
```sh
./build/verifier.build/verifier {0,1} <id>
```


## License
[GNU General Public License v2.0 only](https://spdx.org/licenses/GPL-2.0-only.html)

## Copyright





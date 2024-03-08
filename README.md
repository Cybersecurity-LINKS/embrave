#  embrave
C-language implementation of a Remote Attestation Framework. Implements an Attester Agent, a Verifier, and a Join service to register agents and Verifiers.

Limitation:
- Only ima-ng format of IMA log is supported at the moment
- Some files must be excluded manually
- Exclusive support of TPM2.0

More details in the documentation LINK.
## Build and install
Refer to the [INSTALL.md](INSTALL.md) file for instructions about building and installing the applications.

## Provisioning
### Golden values database and the exclude list database
A python script is provided to create the database of trusted values. In case of known files to be excluded in the verification, add the file or path name in the file ./script/exclude.txt one per line. Then run this Python script on the Attester Agent. It will take some time.
```sh
sudo python3 ./script/goldenvalue_db_generator.py sha256 /
```
If you subsequently need to add other files/paths to the exclude list, you can use the following Python script
```sh
sudo python3 ./script/add_excludelist.py <path/file_to_exclude>
```

### Config file

link to documentation

### Remote Attestor Preparation
Copy the goldenvalue database to the path defined by the config file

## Execution
First run the chosen MQTT client on a trusted device in the group, e.g.
```sh
mosquitto -v
```

### Join Service
Run the Join Service in a trusted device 
```sh
sudo ./join_service.build/join_service
```

### Verifier
Run the Verifier in a trusted device
```sh
sudo ./verifier.build/verifier
```

### Attester Agent
Run the Attester Agent in the device to be attested
```sh
sudo ./agent.build/attester_server
```

## License
[GNU General Public License v2.0 only](https://spdx.org/licenses/GPL-2.0-only.html)







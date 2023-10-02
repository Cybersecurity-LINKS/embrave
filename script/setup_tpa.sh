# create a send folder
mkdir -p ./to_send

#create the tpm keys
sudo ./script/create_tpm_keys.sh

#create the tls keys
sudo ./script/create_certificates.sh

#create the goldenvalue db
sudo python3 ./script/goldenvalue_db_generator.py sha256 /

#copy the file to send
cp ./Agents/Remote_Attestor/AKs/ak.pub.pem ./to_send/
cp ./Server/certs/server.crt ./to_send/
cp ./Protocols/Explicit/goldenvalues.db ./to_send/
cp ./Server/certs/ca.crt ./to_send/
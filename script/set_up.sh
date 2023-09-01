

#create sha256 ak digest
var=$(openssl dgst -sha256 ./Agents/Remote_Attestor/AKs/ak.pub.pem)
sha256=$(echo "${var#*= }")

#create remote attestor binding database
python3 ./script/ra_db.py $sha256 ../../Agents/Remote_Attestor/AKs/ak.pub.pem ../certs/server.crt file:../../Protocols/Explicit/goldenvalues.db
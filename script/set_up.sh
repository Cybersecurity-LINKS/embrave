var=$(openssl dgst -sha256 ./Agents/Remote_Attestor/AKs/ak.pub.pem)
param=$(echo "${var#*= }")
python3 ./script/ra_db.py $param /Agents/Remote_Attestor/AKs/ak.pub.pem /Server/certs/server.crt /Protocols/Explicit/goldenvalues.db
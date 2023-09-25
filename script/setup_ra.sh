mkdir -p ./to_receive

scp -pr root@192.168.85.203:/sources/lemon/to_send ./to_receive

cp ./to_receive/to_send/ak.pub.pem ./Agents/Remote_Attestor/AKs/ak.pub.imx.pem
cp ./to_receive/to_send/server.crt ./Server/certs/server.imx.crt
#mv ./to_receive/to_send/goldenvalues.db ./Protocols/Explicit/goldenvalues.imx.db
cp ./to_receive/to_send/ca.crt ./Server/certs/ca.imx.crt
#create sha256 ak digest
var=$(openssl dgst -sha256 ./Agents/Remote_Attestor/AKs/ak.pub.imx.pem)
sha256=$(echo "${var#*= }")

#create remote attestor binding database
python3 ./script/ra_db.py $sha256 ../../Agents/Remote_Attestor/AKs/ak.pub.imx.pem ../certs/server.imx.crt file:../../Protocols/Explicit/goldenvalues.imx.db ../certs/ca.imx.crt
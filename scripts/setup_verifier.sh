
#scp -pr root@192.168.85.203:/sources/lemon/to_send ./to_receive
LEMONDIR=/home/ale/Scrivania/lemon
#cp ./to_receive/to_send/ak.pub.pem ./Agents/Remote_Attestor/AKs/ak.pub.imx.pem
#cp ./to_receive/to_send/server.crt ./Server/certs/server.imx.crt
#mv ./to_receive/to_send/goldenvalues.db ./Protocols/Explicit/goldenvalues.imx.db
#cp ./to_receive/to_send/ca.crt ./Server/certs/ca.imx.crt
#create sha256 ak digest
var=$(openssl dgst -sha256 ${LEMONDIR}/certs/ak.pub.pem)
sha256=$(echo "${var#*= }")

#create remote attestor binding database
python3 ./scripts/verifier_db.py $sha256 ${LEMONDIR}/certs/ak.pub.pem ${LEMONDIR}/certs/server.crt file:${LEMONDIR}/certs/goldenvalues.db ${LEMONDIR}/certs/ca.crt
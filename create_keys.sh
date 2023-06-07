tpm2_clear
#take ownership ?
sudo tpm2_createek  -c 0x81000003 -u /etc/tc/ek.pub.pem -f pem
sudo tpm2_createak  -C 0x81000003 -c ak.ctx -u /etc/tc/ak.pub.pem -f pem -n /etc/tc/ak.name
sudo tpm2_evictcontrol -c ak.ctx 0x81000004
#rm ak.ctx?
#pcr seal 0 1 2 ?
#remove tpm clear possibility
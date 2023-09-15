if [ $# != 2 ]
  then
    echo "Arguments error: usage ./test_no_tls_cert.sh listen_ip tls(1,0)"
    exit 1
fi

mkdir ./tnp
mv ./Agents/Remote_Attestor/AKs/ak.pub.pem ./tnp/ak.pub.pem
(cd ./Server/Verifier/ && sudo ./client $1 1)
mv  ./tnp/ak.pub.pem ./Agents/Remote_Attestor/AKs/ak.pub.pem 
rm -d tnp
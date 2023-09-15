if [ $# != 1 ]
  then
    echo "Arguments error: usage ./test_no_tls_cert.sh listen_ip"
    exit 1
fi

mkdir ./tnp
mv ./Server/certs/server.crt ./tnp/server.crt
(cd ./Server/Verifier/ && sudo ./client $1 1)
mv  ./tnp/server.crt ./Server/certs/server.crt 
rm -d tnp
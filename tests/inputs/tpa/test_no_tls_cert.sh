if [ $# != 2 ]
  then
    echo "Arguments error: usage ./test_no_tls_cert.sh tcp://listen_ip_no_tls:port tcp://listen_ip_tls:port"
    exit 1
fi

mkdir ./tnp
mv ./Server/certs/server.crt ./tnp/server.crt
(cd ./Server/Attester/ && sudo ./TPA $1 $2)
mv  ./tnp/server.crt ./Server/certs/server.crt 
rm -d tnp
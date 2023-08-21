if [ $# != 2 ]
  then
    echo "Arguments error: usage ./TPA_build.sh tcp://listen_ip_no_tls:port tcp://listen_ip_tls:port"
    exit 1
fi


cd ./Server/Attester/
make 
sudo ./TPA $1 $2
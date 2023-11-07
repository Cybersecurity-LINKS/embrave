if [ $# != 2 ]
  then
    echo "Arguments error: usage ./attester_build.sh tcp://listen_ip_no_tls:port tcp://listen_ip_tls:port"
    exit 1
fi

cd src/attester
sudo ./attester_server $1 $2
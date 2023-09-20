if [ $# != 3 ]
  then
    echo "Arguments error: usage ./PA_build.sh listen_ip int_tls(0,1)  tpa db id"
    exit 1
fi
cd ./Server/Verifier/
make 
sudo ./client $1 $2 $3
if [ $# != 3 ]
  then
    echo "Arguments error: usage ./PA_build.sh listen_ip int_tls(0,1)  tpa db id"
    exit 1
fi
cd src/verifier/
make 
sudo ./verifier $1 $2 $3
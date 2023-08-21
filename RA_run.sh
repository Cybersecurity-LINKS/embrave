if [ $# != 2 ]
  then
    echo "Arguments error: usage ./RA_run.sh listen_ip int_tls(0,1)"
    exit 1
fi
for ((i=1; i<=500; i++))
do
    (cd ./Server/Verifier/ && sudo ./client $1 $2)
    echo $i
    #sleep 5
done
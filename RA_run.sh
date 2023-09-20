if [ $# != 3 ]
  then
    echo "Arguments error: usage ./RA_run.sh listen_ip int_tls(0,1) tpa db id"
    exit 1
fi
for ((i=1; i<=100; i++)) #sudo valgrind --leak-check=yes
do
    #(cd ./Server/Verifier/ && sudo ./client $1 $2)
    var2=$(( ($RANDOM % 2) + 0 ))
    echo "tls?: $var2"
    (cd ./Server/Verifier/ && sudo ./client $1 $var2 $3)
    echo "RUN: $i"
    if [ $? != 0 ]
        then
    exit 1
    fi
    var=$(( ($RANDOM % 80) + 1 ))
    
    echo "Sleep: $var"
    sleep $var
done
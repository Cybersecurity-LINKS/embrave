for ((i=1; i<=500; i++))
do
    (cd ./Server/Verifier/ && sudo ./client)
    echo $i
    #sleep 5
done
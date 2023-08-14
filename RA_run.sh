for ((i=1; i<=100; i++))
do
    (cd ./Server/Verifier/ && sudo ./client)
    echo $?
    #sleep 5
done
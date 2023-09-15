if [ $# != 2 ]
  then
    echo "Arguments error: usage ./test_no_tls_cert.sh listen_ip tls(1,0)"
    exit 1
fi

mkdir ./tnp
mv ./Protocols/Explicit/goldenvalues.db ./tnp/goldenvalues.db
(cd ./Server/Verifier/ && sudo ./client $1 1)
mv  ./tnp/goldenvalues.db ./Protocols/Explicit/goldenvalues.db 
rm -d tnp
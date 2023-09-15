if [ $# != 2 ]
  then
    echo "Arguments error: usage ./test_no_tls_cert.sh listen_ip tls(1,0)"
    exit 1
fi

mkdir ./tnp
mv ./Agents/Remote_Attestor/tpa.db ./tnp/tpa.db
(cd ./Server/Verifier/ && sudo ./client $1 1)
mv  ./tnp/tpa.db ./Agents/Remote_Attestor/tpa.db 
rm -d tnp
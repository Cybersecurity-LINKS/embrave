## Common parameters
SUBJ="/C=IT/ST=Turin/L=Docks/O=Links/CN=tpa"

## Generate CA
openssl genrsa -out ../Server/certs/ca.key 2048
openssl req -new -x509 -days 365 -key ../Server/certs/ca.key -out ../Server/certs/ca.crt \
  -subj /C=IT/ST=Turin/L=Links/O=cyb/CN=me 

## Generate client cert
openssl genrsa -out ../Server/certs/client.key 2048
openssl req -new -key ../Server/certs/client.key -out ../Server/certs/client.csr -subj $SUBJ
openssl x509 -req -days 365 -in ../Server/certs/client.csr -CA ../Server/certs/ca.crt \
  -CAkey ../Server/certs/ca.key -set_serial 01 -out ../Server/certs/client.crt

## Generate server cert
openssl genrsa -out ../Server/certs/server.key 2048
openssl req -new -key ../Server/certs/server.key -out ../Server/certs/server.csr -subj $SUBJ
openssl x509 -req -days 365 -in ../Server/certs/server.csr -CA ../Server/certs/ca.crt \
  -CAkey ../Server/certs/ca.key -set_serial 01 -out ../Server/certs/server.crt
#!/usr/bin/env bash
set -euo pipefail

N=5
SUCCESSFULL=0
FAIL=0

echo "=== TPM2 Sealing/Unsealing Test (Trusted state) ==="
mkdir -p ./tmp
cd ./tmp

echo "[1] Secret creation ..."
echo "secret file" > secret.txt
 
echo "[2] Primary Key creation"
tpm2_createprimary -G ecc -C o -c primary.ctx > /dev/null

for ((i=1; i<=N; i++)); do
 
    echo "[5] Sealed Object creation..."
    tpm2_create \
        -C primary.ctx \
        -u sealed.pub \
        -r sealed.priv \
        -i secret.txt \
    
    echo "[6] Load sealed object in the TPM..."
    tpm2_load -C primary.ctx -u sealed.pub -r sealed.priv -c sealed.ctx

    echo "[7] Unseal of sealed object ..."
    if tpm2_unseal -c sealed.ctx > unsealed.txt; then
        SUCCESSFULL=$((SUCCESSFULL+1))
        echo "Unseal OK"
        cat unsealed.txt
    else
        echo "Unseal KO"
        FAIL=$((FAIL+1))
    fi
done
echo "===  Test Ended ==="
echo "       Success Rate, target 99% => result: ${SUCCESSFULL}/${N} " 
echo

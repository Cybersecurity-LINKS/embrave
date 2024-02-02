#!/bin/bash

# Directory containing the CA certificates
ca_directory="../tpm_ca_certs_hash_dir"
cp -r "../tpm_ca_certs" $ca_directory

# Array to keep track of the number of files with the same hash
declare -A hash_counts

# For each .pem file in the directory
for ca_file in "$ca_directory"/*.pem; do
    # Get the hash value of the certificate's subject name
    hash_value=$(openssl x509 -noout -subject_hash -in "$ca_file")

    # Get the current count for this hash value and increment it
    count=${hash_counts["$hash_value"]}

    # If count is not set, initialize it to zero
    if [ -z "$count" ]; then
        count=0
    fi

    hash_counts["$hash_value"]=$((count + 1))

    # Rename the file with the hash value and count
    mv "$ca_file" "$ca_directory/$hash_value.$count"
done

#!/usr/bin/python3
# -*- coding: utf-8 -*-
import hashlib
import codecs
import enum
import sys

from typing import Optional

class Hash(str, enum.Enum):
    SHA1 = 'sha1'
    SHA256 = 'sha256'
    SHA384 = 'sha384'
    SHA512 = 'sha512'
    SM3_256 = 'sm3_256'


    def hash(self, data: bytes) -> Optional[bytes]:
        if self == Hash.SHA1:
            return hashlib.sha1(data).hexdigest()
        if self == Hash.SHA256:
            return hashlib.sha256(data).hexdigest()
        if self == Hash.SHA384:
            return hashlib.sha384(data).hexdigest()
        if self == Hash.SHA512:
            return hashlib.sha512(data).hexdigest()
        if self == Hash.SM3_256:
            # SM3 might not be guaranteed to be there
            try:
                return hashlib.new("sm3", data).hexdigest()
            except ValueError:
                return None

        return None

    def start_hash(self) -> Optional[bytes]:
        if self == Hash.SHA1:
            return codecs.decode('0'*40, 'hex')
        if self == Hash.SHA256 or self == Hash.SM3_256:
            return codecs.decode('0'*64, 'hex')
        if self == Hash.SHA384:
            return codecs.decode('0'*96, 'hex')
        if self == Hash.SHA512:
            return codecs.decode('0'*128, 'hex')
        
    def ff_hash(self) -> Optional[bytes]:
        if self == Hash.SHA1:
            return codecs.decode('f'*40, 'hex')
        if self == Hash.SHA256 or self == Hash.SM3_256:
            return codecs.decode('f'*64, 'hex')
        if self == Hash.SHA384:
            return codecs.decode('f'*96, 'hex')
        if self == Hash.SHA512:
            return codecs.decode('f'*128, 'hex')
    

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Required parameters: \n-1- hash algorithm \n-2- extended hash value (input to tpm2_pcrextend)  \n \nOutput:\n- PCR final value\n")
        sys.exit(1)
                
    try:
        hash_alg = Hash(sys.argv[1].lower())
        
    except ValueError:
        print("The hash algorithm %s is not supported. Supported hash algorithms are: [%s]" % (hash_alg, ', '.join(h.value for h in Hash)))
        sys.exit(1)
        
        
    extended_hash = codecs.decode(sys.argv[2].lower(), 'hex')
    
    # pcr_value = codecs.decode(sys.argv[3].lower(), 'hex')
    
    
    start_pcr_value = hash_alg.start_hash() 
    #start_pcr_value = hash_alg.ff_hash()
    
    # running_hash = hash_alg.hash(start_pcr_value + extended_hash)
    pcr_value = hash_alg.hash(start_pcr_value + extended_hash)
    
    # if running_hash == pcr_value:
    #     #print("PCR MATCH!")
    #     sys.exit(0)
    # else:
    #     print("ERROR: PCR mismatch!")
    #     sys.exit(1)
 
    # Return the final PCR value as an hex
    print('0x' + pcr_value.upper())

    sys.exit(0)
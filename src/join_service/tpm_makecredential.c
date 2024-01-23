// Copyright (C) 2023 Fondazione LINKS 

// This program is free software; you can redistribute it and/or modify 
// it under the terms of the GNU General Public License as published by the Free Software Foundation; version 2.

// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
// See the GNU General Public License for more details.

// You should have received a copy of the GNU General Public License along with this program; if not, 
// write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

#include <openssl/pem.h>
#if OPENSSL_VERSION_NUMBER < 0x30000000L
#include <openssl/rand.h>
#else
#include <openssl/core_names.h>
#endif

#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include "mongoose.h"
#include "tpm_makecredential.h"


//https://github.com/tpm2-software/tpm2-tools/blob/master/tools/tpm2_makecredential
//https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_makecredential.1.md

static tpm_makecred_ctx ctx = {
    .object_name = TPM2B_EMPTY_INIT,
    .public = TPM2B_EMPTY_INIT,
    .credential = TPM2B_EMPTY_INIT,
    //.key_type = "rsa",
};

tool_rc make_external_credential_and_save(unsigned char **out_buff);
void set_default_TCG_EK_template(TPMI_ALG_PUBLIC alg);

static bool load_public_RSA_from_key(EVP_PKEY *key, TPM2B_PUBLIC *pub) {

    bool result = false;
    TPMT_PUBLIC *pt = &pub->publicArea;
    pt->type = TPM2_ALG_RSA;

    TPMS_RSA_PARMS *rdetail = &pub->publicArea.parameters.rsaDetail;
    /*
     * If the scheme is not TPM2_ALG_ERROR (0),
     * its a valid scheme so don't set it to NULL scheme
     */
    if (rdetail->scheme.scheme == TPM2_ALG_ERROR) {
        rdetail->scheme.scheme = TPM2_ALG_NULL;
        rdetail->symmetric.algorithm = TPM2_ALG_NULL;
        rdetail->scheme.details.anySig.hashAlg = TPM2_ALG_NULL;
    }

    /* NULL out sym details if not already set */
    TPMT_SYM_DEF_OBJECT *sym = &rdetail->symmetric;
    if (sym->algorithm == TPM2_ALG_ERROR) {
        sym->algorithm = TPM2_ALG_NULL;
        sym->keyBits.sym = 0;
        sym->mode.sym = TPM2_ALG_NULL;
    }

#if OPENSSL_VERSION_NUMBER < 0x30000000L
    const BIGNUM *n; /* modulus */
    const BIGNUM *e; /* public key exponent */

    RSA *k = EVP_PKEY_get0_RSA(key);
    if (!k) {
        LOG_ERR("Could not retrieve RSA key");
        goto out;
    }

    RSA_get0_key(k, &n, &e, NULL);
#else
    BIGNUM *n = NULL; /* modulus */
    BIGNUM *e = NULL; /* public key exponent */

    int rc = EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_N, &n);
    if (!rc) {
        LOG_ERR("Could not read public modulus N");
        goto out;
    }

    rc = EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, &e);
    if (!rc) {
        LOG_ERR("Could not read public exponent E");
        goto out;
    }
#endif
    /*
     * The size of the modulus is the key size in RSA, store this as the
     * keyBits in the RSA details.
     */
    rdetail->keyBits = BN_num_bytes(n) * 8;
    switch (rdetail->keyBits) {
    case 1024: /* falls-through */
    case 2048: /* falls-through */
    case 4096: /* falls-through */
        break;
    default:
        LOG_ERR("RSA key-size %u is not supported", rdetail->keyBits);
        goto out;
    }

    /* copy the modulus to the unique RSA field */
    pt->unique.rsa.size = rdetail->keyBits / 8;
    int success = BN_bn2bin(n, pt->unique.rsa.buffer);
    if (!success) {
        LOG_ERR("Could not copy public modulus N");
        goto out;
    }

    unsigned long exp = BN_get_word(e);
    if (exp == 0xffffffffL) {
        LOG_ERR("Could not copy public exponent E");
        goto out;
    }
    rdetail->exponent = exp;

    result = true;
out:
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    /* k,n,e point to internal structrues and must not be freed after use */
#else
    BN_free(n);
    BN_free(e);
#endif
    return result;
}

static int read_der_key_from_buf(unsigned char* ek_cert, int cert_len){
    BIO *bio;
    X509 *cert;
    EVP_PKEY *pkey;

    /* Create a memory BIO */
    bio = BIO_new_mem_buf((void *) ek_cert, cert_len);
    if (!bio) {
        fprintf(stderr, "ERROR: reading EK certificate buffer.\n");
        return 1;
    }

    /* Read the DER certificate from the BIO */
    cert = d2i_X509_bio(bio, NULL);
    if (!cert) {
        fprintf(stderr, "ERROR: reading EK certificate from BIO.\n");
        BIO_free(bio);
        return 1;
    }

    /* Extract the public key from the certificate */
    pkey = X509_get_pubkey(cert);
    if (pkey == NULL) {
        fprintf(stderr, "ERROR: Failed to get EK public key\n");
        X509_free(cert);
        BIO_free(bio);
        return 1;
    }

    /* 
     * Determine the type of the key and populate the TPM2B_PUBLIC structure  * accordingly
     */
    int type = EVP_PKEY_base_id(pkey);
    if (type == EVP_PKEY_RSA) {
        RSA *rsa = EVP_PKEY_get1_RSA(pkey);
        if (rsa == NULL) {
            fprintf(stderr, "Failed to get RSA key\n");
            EVP_PKEY_free(pkey);
            X509_free(cert);
            BIO_free(bio);
            return 1;
        }

        /* read the key dimension */
        // const BIGNUM *n;
        // RSA_get0_key(rsa, &n, NULL, NULL);

        /* set TPM2B_PUBLIC struct */
        ctx.public.publicArea.type = TPM2_ALG_RSA;
        // ctx.public.publicArea.unique.rsa.size = BN_num_bytes(n);
        // BN_bn2bin(n, ctx.public.publicArea.unique.rsa.buffer);
        // RSA_free(rsa);
        if(!load_public_RSA_from_key(pkey, &ctx.public)){
            fprintf(stderr, "Failed to load RSA key\n");
            EVP_PKEY_free(pkey);
            X509_free(cert);
            BIO_free(bio);
            return 1;
        }

    } else if (type == EVP_PKEY_EC) {
        EC_KEY *ec = EVP_PKEY_get1_EC_KEY(pkey);
        if (ec == NULL) {
            fprintf(stderr, "Failed to get EC key\n");
            EVP_PKEY_free(pkey);
            X509_free(cert);
            BIO_free(bio);
            return 1;
        }
        // Populate ctx.public with the EC key details
        // This part depends on the specifics of your TPM2B_PUBLIC structure and the EC key
        // You may need to convert the EC key into a format suitable for your TPM2B_PUBLIC structure
        EC_KEY_free(ec);
    } else {
        fprintf(stderr, "Unsupported key type\n");
        EVP_PKEY_free(pkey);
        X509_free(cert);
        BIO_free(bio);
        return 1;
    }

    /* Clean up */
    EVP_PKEY_free(pkey);
    X509_free(cert);
    BIO_free(bio);

    return 0;
}

/* EVP_PKEY *read_pubkey_from_pem_file(FILE *file) {
    X509 *cert;
    EVP_PKEY *pkey;

    // Read the X509 certificate from the file
    cert = PEM_read_X509(file, NULL, NULL, NULL);
    if (cert == NULL) {
        return NULL;
    }

    // Get the public key from the certificate
    pkey = X509_get_pubkey(cert);
    if (pkey == NULL) {
        X509_free(cert);
        return NULL;
    }

    // Clean up
    X509_free(cert);

    return pkey;
} */

/* static bool load_public_RSA_from_pem(FILE *f, const char *path,
        TPM2B_PUBLIC *pub) {

    //
     // Public PEM files appear in two formats:
     // 1. PEM format, read with PEM_read_RSA_PUBKEY
     // 2. PKCS#1 format, read with PEM_read_RSAPublicKey
     //
     // See:
     //  - https://stackoverflow.com/questions/7818117/why-i-cant-read-openssl-generated-rsa-pub-key-with-pem-read-rsapublickey
     //
    EVP_PKEY *k = // PEM_read_PUBKEY(f, NULL, NULL, NULL);
                    read_pubkey_from_pem_file(f);
    if (!k) {
        ERR_print_errors_fp(stderr);
        LOG_ERR("Reading public PEM file \"%s\" failed", path);
        return false;
    }

    bool result = false;
    if (EVP_PKEY_base_id(k) == EVP_PKEY_RSA) {
        result = load_public_RSA_from_key(k, pub);
    }

    EVP_PKEY_free(k);

    return result;
} */


/* bool tpm_load_public(char *buff, int buff_size, TPMI_ALG_PUBLIC alg,
        TPM2B_PUBLIC *pub) {

    // Create a memory stream
    FILE *stream = fmemopen(buff, buff_size, "rb");
    if (stream == NULL) {
        fprintf(stderr, "Failed to open certificate memory stream\n");
        //free(buff);
        return false;
    }

    bool result = false;

    switch (alg) {
    case TPM2_ALG_RSA:
        result = load_public_RSA_from_pem(stream, "placeholder", pub);
        break;
    case TPM2_ALG_ECC:
        //result = load_public_ECC_from_pem(stream, "placeholder", pub);
        break;
        //Skip AES here, as we can only load this one from a private file 
    default:
        LOG_ERR("Unkown public format: 0x%x", alg);
    }

    fclose(stream);

    return result;
} */

/* static int convert_der_to_pem(unsigned char *der_data, int der_len, unsigned char **pem_data, int *pem_len) {
    BIO *bio_der, *bio_pem;
    X509 *cert;
    BUF_MEM *pem_ptr;

    // Create a BIO for the DER data
    bio_der = BIO_new_mem_buf(der_data, der_len);
    if (bio_der == NULL) {
        return -1;
    }

    // Read the DER certificate from the BIO
    cert = d2i_X509_bio(bio_der, NULL);
    BIO_free(bio_der);
    if (cert == NULL) {
        return -1;
    }

    // Create a BIO for the PEM data
    bio_pem = BIO_new(BIO_s_mem());
    if (bio_pem == NULL) {
        X509_free(cert);
        return -1;
    }

    // Write the X509 object to the PEM BIO
    if (!PEM_write_bio_X509(bio_pem, cert)) {
        BIO_free(bio_pem);
        X509_free(cert);
        return -1;
    }

    // Read the PEM data from the BIO
    BIO_get_mem_ptr(bio_pem, &pem_ptr);
    *pem_data = (unsigned char *)malloc(pem_ptr->length + 1);
    if (*pem_data == NULL) {
        BIO_free(bio_pem);
        X509_free(cert);
        return -1;
    }
    memcpy(*pem_data, pem_ptr->data, pem_ptr->length);
    (*pem_data)[pem_ptr->length] = '\0';
    *pem_len = pem_ptr->length;

    // Clean up
    BIO_free(bio_pem);
    X509_free(cert);

    return 0;
} */

//input
//-u EK PEM
//-s The secret which will be protected by the key derived from the random seed. It can be specified as a file or passed from stdin
//-n The name of the key for which certificate is to be created
//output
//TPM2B_ID_OBJECT *cred, TPM2B_ENCRYPTED_SECRET *secret

/* it is resposability of the caller to free out_buf */
int tpm_makecredential (unsigned char* ek_cert_der, int ek_cert_len, unsigned char* secret, unsigned char* name, size_t name_size, unsigned char **out_buff){

    TPMI_ALG_PUBLIC alg = TPM2_ALG_RSA;

    /* if (ctx.public_key_path) {
        bool result = alg != TPM2_ALG_NULL ?
            tpm2_openssl_load_public(ctx.public_key_path, alg,
            &ctx.public) : files_load_public(ctx.public_key_path, &ctx.public);
        if (!result) {
            return tool_rc_general_error;
        }
    } */
    unsigned char *pem_data;
    int pem_len;

    /* if(convert_der_to_pem(ek_cert_der, ek_cert_len, &pem_data, &pem_len) != 0){
        fprintf(stderr, "ERROR: Failed to convert DER to PEM\n");
        return tool_rc_general_error;
    } */

    /* if(!tpm_load_public(pem_data, pem_len, alg, &ctx.public)){
        fprintf(stderr, "ERROR: Failed to load public key\n");
        return tool_rc_general_error;
    } */

    if(read_der_key_from_buf(ek_cert_der, ek_cert_len)){
        fprintf(stderr, "ERROR: Failed to load public key\n");
        return tool_rc_general_error;
    }

    /* 
     * name is already binary
     */
    ctx.object_name.size = name_size;
    memcpy(ctx.object_name.name, name, name_size);

#ifdef DEBUG
    printf("AK_NAME: ");
    for(int k=0; k<name_size; k++){
        printf("%02x", ctx.object_name.name[k]);
    }
    printf("\n");
#endif

    /*
     * Since it is a PEM we will fixate the key properties from TCG EK
     * template since we had to choose "a template".
     */
    ctx.key_type = "rsa";
    if (ctx.key_type) {
        /*  ctx.public.publicArea.type */
        set_default_TCG_EK_template(alg);
    }

/*     if (!ctx.flags.s) {
        LOG_ERR("Specify the secret either as a file or a '-' for stdin");
        return tool_rc_option_error;
    }

    if (!ctx.flags.e || !ctx.flags.n || !ctx.flags.o) {
        LOG_ERR("Expected mandatory options e, n, o.");
        return tool_rc_option_error;
    } */

    /*
     * Maximum size of the allowed secret-data size  to fit in TPM2B_DIGEST
     */
    ctx.credential.size = strlen(secret);
    memcpy(ctx.credential.buffer, secret, ctx.credential.size);

#ifdef DEBUG   
    printf("Loaded secret: %s\n", ctx.credential.buffer);
#endif

    /* read the secret from a buffer */
    /* bool result = files_load_bytes_from_buffer_or_file_or_stdin(secret,
        NULL, &ctx.credential.size, ctx.credential.buffer);
    if (!result) {
        return -1;
    } */

    /*
     * If input was read from stdin, check if a larger data set was specified
     * and error out.
     */
    if (ctx.credential.size > TPM2_SHA512_DIGEST_SIZE) {
        LOG_ERR("Size is larger than buffer, got %d expected less than or equal"
        "to %d", ctx.credential.size, TPM2_SHA512_DIGEST_SIZE);
        return -1;
    }

    make_external_credential_and_save(out_buff);
    return 0;
}

/* it is resposability of the caller to free out_buf */
static bool write_cred_and_secret(TPM2B_ID_OBJECT *cred, TPM2B_ENCRYPTED_SECRET *secret, unsigned char **out_buff) {

    bool result = false;

    // Allocate a buffer large enough to hold the output
    // You may need to adjust the size depending on your needs
    size_t buffer_size = 1024;
    *out_buff = malloc(buffer_size);
    if (out_buff == NULL) {
        fprintf(stderr, "ERROR: Failed to allocate memory for buffer\n");
        return -1;
    }

    // Create a memory stream
    FILE *stream = fmemopen(*out_buff, buffer_size, "wb+");
    if (stream == NULL) {
        fprintf(stderr, "ERROR: Failed to open memory stream\n");
        free(out_buff);
        return -1;
    }

    result = files_write_header(stream, 1);
    if (!result) {
        LOG_ERR("Could not write version header");
        goto out;
    }

    result = files_write_16(stream, cred->size);
    if (!result) {
        LOG_ERR("Could not write credential size");
        goto out;
    }

    result = files_write_bytes(stream, cred->credential, cred->size);
    if (!result) {
        LOG_ERR("Could not write credential data");
        goto out;
    }

    result = files_write_16(stream, secret->size);
    if (!result) {
        LOG_ERR("Could not write secret size");
        goto out;
    }

    result = files_write_bytes(stream, secret->secret, secret->size);
    if (!result) {
        LOG_ERR("Could not write secret data");
        goto out;
    }

    result = true;

out:
    fclose(stream);
    return result;
}

tool_rc make_external_credential_and_save(unsigned char **out_buff) {

    /*
     * Get name_alg from the public key
     */
    TPMI_ALG_HASH name_alg = ctx.public.publicArea.nameAlg;

    /*
     * Generate and encrypt seed
     */
    TPM2B_DIGEST seed = TPM2B_TYPE_INIT(TPM2B_DIGEST, buffer);
    TPM2B_ENCRYPTED_SECRET encrypted_seed = TPM2B_EMPTY_INIT;
    unsigned char label[10] = { 'I', 'D', 'E', 'N', 'T', 'I', 'T', 'Y', 0 };

#ifdef DEBUG
    printf("Size: %u\n", ctx.public.size);
    printf("Type: %u\n", ctx.public.publicArea.type);
    printf("Name algorithm: %u\n", ctx.public.publicArea.nameAlg);
    printf("Object attributes: 0x%X\n", ctx.public.publicArea.objectAttributes);
#endif

    bool res = tpm2_identity_util_share_secret_with_public_key(&seed,
            &ctx.public, label, 9, &encrypted_seed);
    if (!res) {
        LOG_ERR("Failed Seed Encryption\n");
        return tool_rc_general_error;
    }

    /*
     * Perform identity structure calculations (off of the TPM)
     */
    TPM2B_MAX_BUFFER hmac_key;
    TPM2B_MAX_BUFFER enc_key;
    res = tpm2_identity_util_calc_outer_integrity_hmac_key_and_dupsensitive_enc_key(
            &ctx.public, &ctx.object_name, &seed, &hmac_key, &enc_key);
    if(!res){
        LOG_ERR("Failed to calculate hmac key and dupsensitive encryption key\n");
        return tool_rc_general_error;
    }

    /*
     * The ctx.credential needs to be marshalled into struct with
     * both size and contents together (to be encrypted as a block)
     */
    TPM2B_MAX_BUFFER marshalled_inner_integrity = TPM2B_EMPTY_INIT;
    marshalled_inner_integrity.size = ctx.credential.size
            + sizeof(ctx.credential.size);
    UINT16 cred_size = ctx.credential.size;
    if (!tpm2_util_is_big_endian()) {
        cred_size = tpm2_util_endian_swap_16(cred_size);
    }
    memcpy(marshalled_inner_integrity.buffer, &cred_size, sizeof(cred_size));
    memcpy(&marshalled_inner_integrity.buffer[2], ctx.credential.buffer,
            ctx.credential.size);

    /*
     * Perform inner encryption (encIdentity) and outer HMAC (outerHMAC)
     */
    TPM2B_DIGEST outer_hmac = TPM2B_EMPTY_INIT;
    TPM2B_MAX_BUFFER encrypted_sensitive = TPM2B_EMPTY_INIT;
    tpm2_identity_util_calculate_outer_integrity(name_alg, &ctx.object_name,
            &marshalled_inner_integrity, &hmac_key, &enc_key,
            &ctx.public.publicArea.parameters.rsaDetail.symmetric,
            &encrypted_sensitive, &outer_hmac);

    /*
     * Package up the info to save
     * cred_bloc = outer_hmac || encrypted_sensitive
     * secret = encrypted_seed (with pubEK)
     */
    TPM2B_ID_OBJECT cred_blob = TPM2B_TYPE_INIT(TPM2B_ID_OBJECT, credential);

    UINT16 outer_hmac_size = outer_hmac.size;
    if (!tpm2_util_is_big_endian()) {
        outer_hmac_size = tpm2_util_endian_swap_16(outer_hmac_size);
    }
    int offset = 0;
    memcpy(cred_blob.credential + offset, &outer_hmac_size,
            sizeof(outer_hmac.size));
    offset += sizeof(outer_hmac.size);
    memcpy(cred_blob.credential + offset, outer_hmac.buffer, outer_hmac.size);
    offset += outer_hmac.size;
    //NOTE: do NOT include the encrypted_sensitive size, since it is encrypted with the blob!
    memcpy(cred_blob.credential + offset, encrypted_sensitive.buffer,
            encrypted_sensitive.size);

    cred_blob.size = outer_hmac.size + encrypted_sensitive.size
            + sizeof(outer_hmac.size);

    return write_cred_and_secret(&cred_blob,
            &encrypted_seed, out_buff) ? tool_rc_success : tool_rc_general_error;
}

void set_default_TCG_EK_template(TPMI_ALG_PUBLIC alg) {

    switch (alg) {
        case TPM2_ALG_RSA:
            ctx.public.publicArea.parameters.rsaDetail.symmetric.algorithm =
                    TPM2_ALG_AES;
            ctx.public.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
            ctx.public.publicArea.parameters.rsaDetail.symmetric.mode.aes =
                    TPM2_ALG_CFB;
            ctx.public.publicArea.parameters.rsaDetail.scheme.scheme = TPM2_ALG_NULL;
            ctx.public.publicArea.parameters.rsaDetail.keyBits = 2048;
            ctx.public.publicArea.parameters.rsaDetail.exponent = 0;
            ctx.public.publicArea.unique.rsa.size = 256;
            break;
        case TPM2_ALG_ECC:
            ctx.public.publicArea.parameters.eccDetail.symmetric.algorithm =
                    TPM2_ALG_AES;
            ctx.public.publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
            ctx.public.publicArea.parameters.eccDetail.symmetric.mode.sym =
                    TPM2_ALG_CFB;
            ctx.public.publicArea.parameters.eccDetail.scheme.scheme = TPM2_ALG_NULL;
            ctx.public.publicArea.parameters.eccDetail.curveID = TPM2_ECC_NIST_P256;
            ctx.public.publicArea.parameters.eccDetail.kdf.scheme = TPM2_ALG_NULL;
            ctx.public.publicArea.unique.ecc.x.size = 32;
            ctx.public.publicArea.unique.ecc.y.size = 32;
            break;
    }

    ctx.public.publicArea.objectAttributes =
          TPMA_OBJECT_RESTRICTED  | TPMA_OBJECT_ADMINWITHPOLICY
        | TPMA_OBJECT_DECRYPT     | TPMA_OBJECT_FIXEDTPM
        | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN;

    static const TPM2B_DIGEST auth_policy = {
        .size = 32,
        .buffer = {
            0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC,
            0x8D, 0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52,
            0x0B, 0x64, 0xF2, 0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA
        }
    };
    TPM2B_DIGEST *authp = &ctx.public.publicArea.authPolicy;
    *authp = auth_policy;

    ctx.public.publicArea.nameAlg = TPM2_ALG_SHA256;
}

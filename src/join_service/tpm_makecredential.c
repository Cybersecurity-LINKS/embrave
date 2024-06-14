// Copyright (C) 2024 Fondazione LINKS 

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

static tpm_makecred_ctx ctx = {
    .object_name = TPM2B_EMPTY_INIT,
    .public = TPM2B_EMPTY_INIT,
    .credential = TPM2B_EMPTY_INIT,
};

static const struct {
    TPMI_ECC_CURVE curve;
    int nid;
} nid_curve_map[] = {
    { TPM2_ECC_NIST_P192, NID_X9_62_prime192v1 },
    { TPM2_ECC_NIST_P224, NID_secp224r1        },
    { TPM2_ECC_NIST_P256, NID_X9_62_prime256v1 },
    { TPM2_ECC_NIST_P384, NID_secp384r1        },
    { TPM2_ECC_NIST_P521, NID_secp521r1        },
#if OPENSSL_VERSION_NUMBER >= 0x10101003L
    { TPM2_ECC_SM2_P256,  NID_sm2              },
#endif
    /*
     * XXX
     * See if it's possible to support the other curves, I didn't see the
     * mapping in OSSL:
     *  - TPM2_ECC_BN_P256
     *  - TPM2_ECC_BN_P638
     *  - TPM2_ECC_SM2_P256
     */
};

tool_rc make_external_credential_and_save(unsigned char **out_buff, size_t *out_buff_size);
void set_default_TCG_EK_template(TPMI_ALG_PUBLIC alg);

/**
 * Maps an OSSL nid as defined obj_mac.h to a TPM2 ECC curve id.
 * @param nid
 *  The nid to map.
 * @return
 *  A valid TPM2_ECC_* or TPM2_ALG_ERROR on error.
 */
static TPMI_ECC_CURVE ossl_nid_to_curve(int nid) {

    unsigned i;
    for (i = 0; i < ARRAY_LEN(nid_curve_map); i++) {
        TPMI_ECC_CURVE c = nid_curve_map[i].curve;
        int n = nid_curve_map[i].nid;

        if (n == nid) {
            return c;
        }
    }

    LOG_ERR("Cannot map nid \"%d\" to TPM ECC curve", nid);
    return TPM2_ALG_ERROR;
}

static bool load_public_ECC_from_key(EVP_PKEY *key, TPM2B_PUBLIC *pub) {

    BIGNUM *y = NULL;
    BIGNUM *x = NULL;
    int nid;
    unsigned keysize;
    bool result = false;

    /*
     * Set the algorithm type
     */
    pub->publicArea.type = TPM2_ALG_ECC;
    TPMS_ECC_PARMS *pp = &pub->publicArea.parameters.eccDetail;

    /*
     * Get the curve type and the public key (X and Y)
     */
#if OPENSSL_VERSION_NUMBER < 0x30000000L
    EC_KEY *k = EVP_PKEY_get0_EC_KEY(key);
    if (!k) {
        LOG_ERR("Could not retrieve ECC key");
        goto out;
    }

    y = BN_new();
    x = BN_new();
    if (!x || !y) {
        LOG_ERR("oom");
        goto out;
    }

    const EC_GROUP *group = EC_KEY_get0_group(k);
    nid = EC_GROUP_get_curve_name(group);
    keysize = (EC_GROUP_get_degree(group) + 7) / 8;

    const EC_POINT *point = EC_KEY_get0_public_key(k);

    int ret = EC_POINT_get_affine_coordinates_tss(group, point, x, y, NULL);
    if (!ret) {
        LOG_ERR("Could not get X and Y affine coordinates");
        goto out;
    }
#else
    char curve_name[80];

    int rc = EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME,
                                            curve_name, sizeof(curve_name), NULL);
    if (!rc) {
        LOG_ERR("Could not read ECC curve name");
        goto out;
    }
    nid = OBJ_txt2nid(curve_name);
    keysize = (EVP_PKEY_bits(key) + 7) / 8;

    rc = EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_X, &x);
    if (!rc) {
        LOG_ERR("Could not read public X coordinate");
        goto out;
    }

    rc = EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_EC_PUB_Y, &y);
    if (!rc) {
        LOG_ERR("Could not read public Y coordinate");
        goto out;
    }
#endif

    /*
     * Set the curve type
     */
    TPM2_ECC_CURVE curve_id = ossl_nid_to_curve(nid); // Not sure what lines up with NIST 256...
    if (curve_id == TPM2_ALG_ERROR) {
        goto out;
    }
    pp->curveID = curve_id;

    /*
     * Copy the X and Y coordinate data into the ECC unique field,
     * ensuring that it fits along the way.
     */
    TPM2B_ECC_PARAMETER *X = &pub->publicArea.unique.ecc.x;
    TPM2B_ECC_PARAMETER *Y = &pub->publicArea.unique.ecc.y;

    if (keysize > sizeof(X->buffer)) {
        LOG_ERR("X coordinate is too big. Got %u expected less than or equal to"
                " %zu", keysize, sizeof(X->buffer));
        goto out;
    }

    if (keysize > sizeof(Y->buffer)) {
        LOG_ERR("X coordinate is too big. Got %u expected less than or equal to"
                " %zu", keysize, sizeof(Y->buffer));
        goto out;
    }

    X->size = BN_bn2binpad(x, X->buffer, keysize);
    if (X->size != keysize) {
        LOG_ERR("Error converting X point BN to binary");
        goto out;
    }

    Y->size = BN_bn2binpad(y, Y->buffer, keysize);
    if (Y->size != keysize) {
        LOG_ERR("Error converting Y point BN to binary");
        goto out;
    }

    /*
     * no kdf - not sure what this should be
     */
    pp->kdf.scheme = TPM2_ALG_NULL;

    /*
     * If the scheme is not TPM2_ALG_ERROR (0),
     * its a valid scheme so don't set it to NULL scheme
     */
    if (pp->scheme.scheme == TPM2_ALG_ERROR) {
        pp->scheme.scheme = TPM2_ALG_NULL;
        pp->scheme.details.anySig.hashAlg = TPM2_ALG_NULL;
    }

    /* NULL out sym details if not already set */
    TPMT_SYM_DEF_OBJECT *sym = &pp->symmetric;
    if (sym->algorithm == TPM2_ALG_ERROR) {
        sym->algorithm = TPM2_ALG_NULL;
        sym->keyBits.sym = 0;
        sym->mode.sym = TPM2_ALG_NULL;
    }

    result = true;
out:
    BN_free(x);
    BN_free(y);
    return result;
}

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

        ctx.public.publicArea.type = TPM2_ALG_RSA;

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
        /* set TPM2B_PUBLIC struct */
        ctx.public.publicArea.type = TPM2_ALG_ECC;
        if(!load_public_ECC_from_key(pkey, &ctx.public)){
            fprintf(stderr, "Failed to load ECC key\n");
            EVP_PKEY_free(pkey);
            X509_free(cert);
            BIO_free(bio);
            return 1;
        }
        
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

/*  
    Tt is resposability of the caller to free out_buf 
    Input:
        ek_cert_der EK der
        secret The secret which will be protected by the key derived from the random seed. It can be specified as a file or passed from stdin
        name The name of the key for which certificate is to be created
    Output:
        -TPM2B_ID_OBJECT *cred, TPM2B_ENCRYPTED_SECRET *secret
*/
int tpm_makecredential (unsigned char* ek_cert_der, int ek_cert_len, unsigned char* secret, unsigned char* name, size_t name_size, unsigned char **out_buff, size_t *out_buff_size){

    /* 
     * Extract the EK pub key from the certificate in DER format
     */

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
     * Set the key properties from TCG EK
     * template since we had to choose "a template".
     */
    
    set_default_TCG_EK_template(ctx.public.publicArea.type);

    /*
     * Maximum size of the allowed secret-data size  to fit in TPM2B_DIGEST
     */
    ctx.credential.size = strlen((char *) secret);
    memcpy(ctx.credential.buffer, secret, ctx.credential.size);

#ifdef DEBUG   
    printf("Loaded secret: %s\n", ctx.credential.buffer);
#endif

    /*
     * If input was read from stdin, check if a larger data set was specified
     * and error out.
     */
    if (ctx.credential.size > TPM2_SHA512_DIGEST_SIZE) {
        LOG_ERR("Size is larger than buffer, got %d expected less than or equal"
        "to %d", ctx.credential.size, TPM2_SHA512_DIGEST_SIZE);
        return -1;
    }

    make_external_credential_and_save(out_buff, out_buff_size);
    return 0;
}

/* it is resposability of the caller to free out_buf */
static bool write_cred_and_secret(TPM2B_ID_OBJECT *cred, TPM2B_ENCRYPTED_SECRET *secret, unsigned char **out_buff, size_t *out_buff_size) {

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

    *out_buff_size = ftell(stream);
    fprintf(stdout, "INFO: tpm_makecredential output size: %d\n", *out_buff_size);

out:
    fclose(stream);
    return result;
}

tool_rc make_external_credential_and_save(unsigned char **out_buff, size_t *out_buff_size) {

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
            &encrypted_seed, out_buff, out_buff_size) ? tool_rc_success : tool_rc_general_error;
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

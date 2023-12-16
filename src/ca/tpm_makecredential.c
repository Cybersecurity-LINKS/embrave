// Copyright (C) 2023 Fondazione LINKS 

// This program is free software; you can redistribute it and/or modify 
// it under the terms of the GNU General Public License as published by the Free Software Foundation; version 2.

// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
// See the GNU General Public License for more details.

// You should have received a copy of the GNU General Public License along with this program; if not, 
// write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

#include "tpm_makecredential.h"


//https://github.com/tpm2-software/tpm2-tools/blob/master/tools/tpm2_makecredential
//https://github.com/tpm2-software/tpm2-tools/blob/master/man/tpm2_makecredential.1.md

static tpm_makecred_ctx ctx = {
    .object_name = TPM2B_EMPTY_INIT,
    .public = TPM2B_EMPTY_INIT,
    .credential = TPM2B_EMPTY_INIT,
};

void tpm_makecredential (void){

    TPMI_ALG_PUBLIC alg = TPM2_ALG_NULL;
    if (ctx.key_type) {
        if (!flags.quiet) {
            LOG_WARN("Because **-G** is specified, assuming input encryption "
                     "public key is in PEM format.");
        }
        alg = tpm2_alg_util_from_optarg(ctx.key_type,
            tpm2_alg_util_flags_asymmetric);
        if (alg == TPM2_ALG_ERROR ||
           (alg != TPM2_ALG_RSA && alg != TPM2_ALG_ECC)) {
            LOG_ERR("Unsupported key type, got: \"%s\"", ctx.key_type);
            return tool_rc_general_error;
        }
    }

    if (ctx.public_key_path) {
        bool result = alg != TPM2_ALG_NULL ?
            tpm2_openssl_load_public(ctx.public_key_path, alg,
            &ctx.public) : files_load_public(ctx.public_key_path, &ctx.public);
        if (!result) {
            return tool_rc_general_error;
        }
    }

    /*
     * Since it is a PEM we will fixate the key properties from TCG EK
     * template since we had to choose "a template".
     */
    if (ctx.key_type) {
        set_default_TCG_EK_template(alg);
    }

    if (!ctx.flags.s) {
        LOG_ERR("Specify the secret either as a file or a '-' for stdin");
        return tool_rc_option_error;
    }

    if (!ctx.flags.e || !ctx.flags.n || !ctx.flags.o) {
        LOG_ERR("Expected mandatory options e, n, o.");
        return tool_rc_option_error;
    }

    /*
     * Maximum size of the allowed secret-data size  to fit in TPM2B_DIGEST
     */
    ctx.credential.size = TPM2_SHA512_DIGEST_SIZE;

    bool result = files_load_bytes_from_buffer_or_file_or_stdin(NULL,
        ctx.input_secret_data, &ctx.credential.size, ctx.credential.buffer);
    if (!result) {
        return tool_rc_general_error;
    }

    /*
     * If input was read from stdin, check if a larger data set was specified
     * and error out.
     */
    if (ctx.credential.size > TPM2_SHA512_DIGEST_SIZE) {
        LOG_ERR("Size is larger than buffer, got %d expected less than or equal"
        "to %d", ctx.credential.size, TPM2_SHA512_DIGEST_SIZE);
        return tool_rc_general_error;
    }







    make_external_credential_and_save();

}

tool_rc make_external_credential_and_save(void) {

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
    tpm2_identity_util_calc_outer_integrity_hmac_key_and_dupsensitive_enc_key(
            &ctx.public, &ctx.object_name, &seed, &hmac_key, &enc_key);

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

    return write_cred_and_secret(ctx.out_file_path, &cred_blob,
            &encrypted_seed) ? tool_rc_success : tool_rc_general_error;
}

static bool write_cred_and_secret(const char *path, TPM2B_ID_OBJECT *cred,
        TPM2B_ENCRYPTED_SECRET *secret) {

    bool result = false;

    FILE *fp = fopen(path, "wb+");
    if (!fp) {
        LOG_ERR("Could not open file \"%s\" error: \"%s\"", path,
                strerror(errno));
        return false;
    }

    result = files_write_header(fp, 1);
    if (!result) {
        LOG_ERR("Could not write version header");
        goto out;
    }

    result = files_write_16(fp, cred->size);
    if (!result) {
        LOG_ERR("Could not write credential size");
        goto out;
    }

    result = files_write_bytes(fp, cred->credential, cred->size);
    if (!result) {
        LOG_ERR("Could not write credential data");
        goto out;
    }

    result = files_write_16(fp, secret->size);
    if (!result) {
        LOG_ERR("Could not write secret size");
        goto out;
    }

    result = files_write_bytes(fp, secret->secret, secret->size);
    if (!result) {
        LOG_ERR("Could not write secret data");
        goto out;
    }

    result = true;

out:
    fclose(fp);
    return result;
}
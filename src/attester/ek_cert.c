// Copyright (C) 2024 Fondazione LINKS 

// This program is free software; you can redistribute it and/or modify 
// it under the terms of the GNU General Public License as published by the Free Software Foundation; version 2.

// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
// See the GNU General Public License for more details.

// You should have received a copy of the GNU General Public License along with this program; if not, 
// write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

#include <unistd.h>
#include "ek_cert.h"

#define EK_SERVER_INTEL "https://ekop.intel.com/ekcertservice/"
#define EK_SERVER_AMD "https://ftpm.amd.com/pki/aia/"

static char *base64_decode(char **split, unsigned int cert_length) ;

static tpm_getekcertificate_ctx ctx = {
    .is_tpm2_device_active = true,
    .is_cert_on_nv = true,
    .cert_count = 0,
    .encoding = ENC_AUTO,
    .ec_cert_path_1 = "ek_rsa_cert.pem",
    .ec_cert_path_2 = "ek_ecc_cert.pem"
};

tool_rc free_ctx(void){

    if (ctx.ec_cert_file_handle_1) {
        fclose(ctx.ec_cert_file_handle_1);
    }

    if (ctx.ec_cert_file_handle_2) {
        fclose(ctx.ec_cert_file_handle_2);
    }

    if (ctx.rsa_cert_buffer) {
        free(ctx.rsa_cert_buffer);
    }

    if (ctx.ecc_cert_buffer) {
        free(ctx.ecc_cert_buffer);
    }

    return tool_rc_success;
}

#define PEM_BEGIN_CERT_LINE "\n-----BEGIN CERTIFICATE-----\n"
#define PEM_END_CERT_LINE "\n-----END CERTIFICATE-----\n"

tool_rc save_cert(struct attester_conf *conf) {

    /*
     * Check if the cert is from INTC based on certificated data containing
     * the EK public hash in addition to the certificate data.
     * If so set the flag.
     */
    bool is_intel_cert = ctx.manufacturer == VENDOR_INTEL;

    if (!is_intel_cert && ctx.rsa_cert_buffer) {
        is_intel_cert = !(strncmp((const char *)ctx.rsa_cert_buffer,
            "{\"pubhash", strlen("{\"pubhash")));
    }

    if (!is_intel_cert && ctx.ecc_cert_buffer) {
        is_intel_cert = !(strncmp((const char *)ctx.ecc_cert_buffer,
            "{\"pubhash", strlen("{\"pubhash")));
    }

    /*
     * Intel EK certificates on the NV-index are already in standard DER format.
     */
    if (is_intel_cert && ctx.is_cert_on_nv) {
        ctx.is_cert_raw = true;
    }

    /*
     *  Convert Intel EK certificates as received in the URL safe variant of
     *  Base 64: https://tools.ietf.org/html/rfc4648#section-5 to PEM
     */
    if (ctx.rsa_cert_buffer && is_intel_cert && !ctx.is_cert_raw) {
        char *split = strstr((const char *)ctx.rsa_cert_buffer, "certificate");
        char *copy_buffer = base64_decode(&split, ctx.rsa_cert_buffer_size);
        ctx.rsa_cert_buffer_size = strlen(PEM_BEGIN_CERT_LINE) +
            strlen(copy_buffer) + strlen(PEM_END_CERT_LINE);
        strcpy((char *)ctx.rsa_cert_buffer, PEM_BEGIN_CERT_LINE);
        strcpy((char *)ctx.rsa_cert_buffer + strlen(PEM_BEGIN_CERT_LINE),
            copy_buffer);
        strcpy((char *)ctx.rsa_cert_buffer + strlen(PEM_BEGIN_CERT_LINE) +
            strlen(copy_buffer), PEM_END_CERT_LINE);
        free(copy_buffer);
    }

    if (ctx.ecc_cert_buffer && is_intel_cert && !ctx.is_cert_raw) {
        char *split = strstr((const char *)ctx.ecc_cert_buffer, "certificate");
        char *copy_buffer = base64_decode(&split, ctx.ecc_cert_buffer_size);
        ctx.ecc_cert_buffer_size = strlen(PEM_BEGIN_CERT_LINE) +
            strlen(copy_buffer) + strlen(PEM_END_CERT_LINE);
        strcpy((char *)ctx.ecc_cert_buffer, PEM_BEGIN_CERT_LINE);
        strcpy((char *)ctx.ecc_cert_buffer + strlen(PEM_BEGIN_CERT_LINE),
            copy_buffer);
        strcpy((char *)ctx.ecc_cert_buffer + strlen(PEM_BEGIN_CERT_LINE) +
            strlen(copy_buffer), PEM_END_CERT_LINE);
        free(copy_buffer);
    }

    bool retval = true;

    if (ctx.ecc_cert_buffer) {
        retval = files_write_bytes(ctx.ec_cert_file_handle_2, ctx.ecc_cert_buffer, ctx.ecc_cert_buffer_size);
        if (!retval) {
            return tool_rc_general_error;
        }

    } else if (ctx.rsa_cert_buffer) {
        retval = files_write_bytes(ctx.ec_cert_file_handle_1, ctx.rsa_cert_buffer, ctx.rsa_cert_buffer_size);
        if (!retval) {
            return tool_rc_general_error;
        }
    }

    return tool_rc_success;
}

char *get_ek_server_address(void) {
    if (ctx.ek_server_addr) // set by CLI
    {
        return ctx.ek_server_addr;
    }

    switch (ctx.manufacturer) {
        case VENDOR_INTEL:
            return EK_SERVER_INTEL;
        case VENDOR_AMD:
            return EK_SERVER_AMD;
        default:
            LOG_ERR("No EK server address found for manufacturer.");
            return NULL;
    }
}

#define AMD_EK_URI_LEN 16 // AMD EK takes first 16 hex chars of hash

unsigned char *hash_ek_public(void) {

    unsigned char *hash = (unsigned char*) malloc(SHA256_DIGEST_LENGTH);
    if (!hash) {
        LOG_ERR("OOM");
        return NULL;
    }

    EVP_MD_CTX *sha256 = EVP_MD_CTX_new();
    if (!hash) {
        LOG_ERR("OOM");
        goto evperr;
    }
    int is_success = EVP_DigestInit(sha256, EVP_sha256());
    if (!is_success) {
        LOG_ERR("EVP_DigestInit failed");
        goto err;
    }

    if (ctx.encoding == ENC_AMD) {
        switch (ctx.out_public->publicArea.type) {
        case TPM2_ALG_RSA: {
            /*
             * hash = sha256(00 00 22 22 || (uint32_t) exp || modulus)
             */
            BYTE buf[4] = { 0x00, 0x00, 0x22, 0x22 }; // Prefix
            is_success = EVP_DigestUpdate(sha256, buf, sizeof(buf));
            if (!is_success) {
                LOG_ERR("EVP_DigestUpdate failed");
                goto err;
            }

            uint32_t exp = ctx.out_public->publicArea.parameters.rsaDetail.exponent;
            if (exp == 0) {
                exp = 0x00010001; // 0 indicates default
            } else {
                LOG_WARN("non-default exponent used");
            }
            buf[3] = (BYTE)exp;
            buf[2] = (BYTE)(exp>>=8);
            buf[1] = (BYTE)(exp>>=8);
            buf[0] = (BYTE)(exp>>8);
            is_success = EVP_DigestUpdate(sha256, buf, sizeof(buf));
            if (!is_success) {
                LOG_ERR("EVP_DigestUpdate failed");
                goto err;
            }

            is_success = EVP_DigestUpdate(sha256,
                    ctx.out_public->publicArea.unique.rsa.buffer,
                    ctx.out_public->publicArea.unique.rsa.size);
            if (!is_success) {
                LOG_ERR("EVP_DigestUpdate failed");
                goto err;
            }
            break;
        }
        case TPM2_ALG_ECC: {
            /*
             * hash = sha256(00 00 44 44 || (uint32_t) exp || modulus)
             */
            BYTE buf[4] = { 0x00, 0x00, 0x44, 0x44 }; // Prefix
            is_success = EVP_DigestUpdate(sha256, buf, sizeof(buf));
            if (!is_success) {
                LOG_ERR("EVP_DigestUpdate failed");
                goto err;
            }
            is_success = EVP_DigestUpdate(sha256,
                    ctx.out_public->publicArea.unique.ecc.x.buffer,
                    ctx.out_public->publicArea.unique.ecc.x.size);
            if (!is_success) {
                LOG_ERR("EVP_DigestUpdate failed");
                goto err;
            }

            is_success = EVP_DigestUpdate(sha256,
                    ctx.out_public->publicArea.unique.ecc.y.buffer,
                    ctx.out_public->publicArea.unique.ecc.y.size);
            if (!is_success) {
                LOG_ERR("EVP_DigestUpdate failed");
                goto err;
            }
            break;
        }
        default:
            LOG_ERR("unsupported EK algorithm");
            goto err;
        }
    } else {
        switch (ctx.out_public->publicArea.type) {
        case TPM2_ALG_RSA:
            is_success = EVP_DigestUpdate(sha256,
                    ctx.out_public->publicArea.unique.rsa.buffer,
                    ctx.out_public->publicArea.unique.rsa.size);
            if (!is_success) {
                LOG_ERR("EVP_DigestUpdate failed");
                goto err;
            }

            if (ctx.out_public->publicArea.parameters.rsaDetail.exponent != 0) {
                LOG_ERR("non-default exponents unsupported");
                goto err;
            }
            BYTE buf[3] = { 0x1, 0x00, 0x01 }; // Exponent
            is_success = EVP_DigestUpdate(sha256, buf, sizeof(buf));
            if (!is_success) {
                LOG_ERR("EVP_DigestUpdate failed");
                goto err;
            }
            break;

        case TPM2_ALG_ECC:
            is_success = EVP_DigestUpdate(sha256,
                    ctx.out_public->publicArea.unique.ecc.x.buffer,
                    ctx.out_public->publicArea.unique.ecc.x.size);
            if (!is_success) {
                LOG_ERR("EVP_DigestUpdate failed");
                goto err;
            }

            is_success = EVP_DigestUpdate(sha256,
                    ctx.out_public->publicArea.unique.ecc.y.buffer,
                    ctx.out_public->publicArea.unique.ecc.y.size);
            if (!is_success) {
                LOG_ERR("EVP_DigestUpdate failed");
                goto err;
            }
            break;

        default:
            LOG_ERR("unsupported EK algorithm");
            goto err;
        }
    }

    is_success = EVP_DigestFinal_ex(sha256, hash, NULL);
    if (!is_success) {
        LOG_ERR("EVP_DigestFinal failed");
        goto err;
    }

    EVP_MD_CTX_free(sha256);
    if (ctx.verbose) {
        tpm2_tool_output("public-key-hash:\n");
        tpm2_tool_output("  sha256: ");
        unsigned i;
        for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            tpm2_tool_output("%02X", hash[i]);
        }
        tpm2_tool_output("\n");
    }

    return hash;
err:
    EVP_MD_CTX_free(sha256);
evperr:
    free(hash);
    return NULL;
}

char *base64_encode(const unsigned char* buffer)
{
    BIO *bio, *b64;
    BUF_MEM *buffer_pointer;

    LOG_INFO("Calculating the base64_encode of the hash of the Endorsement"
             "Public Key:");

    if (buffer == NULL) {
        LOG_ERR("hash_ek_public returned null");
        return NULL;
    }

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, buffer, SHA256_DIGEST_LENGTH);
    UNUSED(BIO_flush(bio));
    BIO_get_mem_ptr(bio, &buffer_pointer);

    /* these are not NULL terminated */
    char *b64text = buffer_pointer->data;
    size_t len = buffer_pointer->length;

    size_t i;
    for (i = 0; i < len; i++) {
        if (b64text[i] == '+') {
            b64text[i] = '-';
        }
        if (b64text[i] == '/') {
            b64text[i] = '_';
        }
    }

    char *final_string = NULL;

    CURL *curl = curl_easy_init();
    if (curl) {
        char *output = curl_easy_escape(curl, b64text, len);
        if (output) {
            final_string = strdup(output);
            curl_free(output);
        }
    }
    curl_easy_cleanup(curl);
    curl_global_cleanup();
    BIO_free_all(bio);

    /* format to a proper NULL terminated string */
    return final_string;
}

#define NULL_TERM_LEN 1 // '\0'

char *encode_ek_public_amd(void) {
    unsigned char *hash = hash_ek_public();
    if (!hash) {
        LOG_ERR("EK hash is null");
        return NULL;
    }
    char *hash_str = malloc(AMD_EK_URI_LEN * 2 + NULL_TERM_LEN);
    for (size_t i = 0; i < AMD_EK_URI_LEN; i++)
    {
        sprintf((char*)(hash_str + (i*2)), "%02x", hash[i]);
    }
    hash_str[AMD_EK_URI_LEN * 2] = '\0';
    return hash_str;
}

char *encode_ek_public_intel(void) {
    unsigned char *hash = hash_ek_public();
    char *b64 = base64_encode(hash);
    free(hash);
    if (!b64) {
        LOG_ERR("base64_encode returned null");
    }
    return b64;
}

char *encode_ek_public(void) {
    if (ctx.encoding == ENC_AMD) {
        return encode_ek_public_amd();
    } else {
        return encode_ek_public_intel();
    }
}
/*
 * As only one cert is downloaded at a time, we can simply use
 * rsa_cert_buffer for either RSA EK cert or ECC EK cert.
 */
size_t writecallback(char *contents, size_t size, size_t nitems,
    void *userdata) {
    UNUSED(userdata);
    const size_t chunk_size = size * nitems;

    if (!chunk_size) {
      return 0;
    }

    const size_t new_used_size = ctx.rsa_cert_buffer_size + chunk_size;
    if (ctx.curl_buffer_size < new_used_size) {
        const size_t new_buf_size = ctx.curl_buffer_size + CURL_MAX_WRITE_SIZE;
        void *new_buf = realloc(ctx.rsa_cert_buffer, new_buf_size);
        if (!new_buf) {
            LOG_ERR("OOM when downloading EK cert");
            return 0;
        }
        ctx.rsa_cert_buffer = new_buf;
        ctx.curl_buffer_size = new_buf_size;
    }

    memcpy(ctx.rsa_cert_buffer + ctx.rsa_cert_buffer_size, contents, chunk_size);
    ctx.rsa_cert_buffer_size += chunk_size;
    return chunk_size;
}

bool retrieve_web_endorsement_certificate(char *uri) {

    #define PATH_JOIN_CHAR_LEN 1            // '/'
    size_t len = strlen(ctx.ek_server_addr) + strlen(uri) + NULL_TERM_LEN +
        PATH_JOIN_CHAR_LEN;
    char *weblink = (char *) malloc(len);
    if (!weblink) {
        LOG_ERR("oom");
        return false;
    }

    bool ret = true;
    ctx.rsa_cert_buffer = malloc(CURL_MAX_WRITE_SIZE);
    if (!ctx.rsa_cert_buffer) {
        LOG_ERR("OOM");
        ret = false;
        goto out_memory;
    }
    ctx.curl_buffer_size = CURL_MAX_WRITE_SIZE;

    CURLcode rc = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (rc != CURLE_OK) {
        LOG_ERR("curl_global_init failed: %s", curl_easy_strerror(rc));
        ret = false;
        goto out_memory;
    }

    CURL *curl = curl_easy_init();
    if (!curl) {
        LOG_ERR("curl_easy_init failed");
        ret = false;
        goto out_global_cleanup;
    }

    /*
     * should not be used - Used only on platforms with older CA certificates.
     */
    if (ctx.SSL_NO_VERIFY) {
        rc = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0);
        if (rc != CURLE_OK) {
            LOG_ERR("curl_easy_setopt for CURLOPT_SSL_VERIFYPEER failed: %s",
                    curl_easy_strerror(rc));
            ret = false;
            goto out_easy_cleanup;
        }
    }

    bool is_slash_append_required =
        strncmp((ctx.ek_server_addr + strlen(ctx.ek_server_addr) - 1), "/", 1);
    if (is_slash_append_required) {
        snprintf(weblink, len, "%s%s%s", ctx.ek_server_addr, "/", uri);
    } else {
        snprintf(weblink, len, "%s%s", ctx.ek_server_addr, uri);
    }

    rc = curl_easy_setopt(curl, CURLOPT_URL, weblink);
    if (rc != CURLE_OK) {
        LOG_ERR("curl_easy_setopt for CURLOPT_URL failed: %s",
                curl_easy_strerror(rc));
        ret = false;
        goto out_easy_cleanup;
    }

    /*
     * If verbose is set, add in diagnostic information for debugging connections.
     * https://curl.haxx.se/libcurl/c/CURLOPT_VERBOSE.html
     */
    rc = curl_easy_setopt(curl, CURLOPT_VERBOSE, (long )ctx.verbose);
    if (rc != CURLE_OK) {
        LOG_ERR("curl_easy_setopt for CURLOPT_VERBOSE failed: %s",
                curl_easy_strerror(rc));
        ret = false;
        goto out_easy_cleanup;
    }

    rc = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writecallback);
    if (rc != CURLE_OK) {
        LOG_ERR("curl_easy_setopt for CURLOPT_WRITEFUNCTION failed: %s",
                curl_easy_strerror(rc));
        ret = false;
        goto out_easy_cleanup;
    }

    rc = curl_easy_setopt(curl, CURLOPT_FAILONERROR, true);
    if (rc != CURLE_OK) {
        LOG_ERR("curl_easy_setopt for CURLOPT_FAILONERROR failed: %s",
                curl_easy_strerror(rc));
        goto out_easy_cleanup;
    }

    rc = curl_easy_perform(curl);
    if (rc != CURLE_OK) {
        LOG_ERR("curl_easy_perform() failed: %s", curl_easy_strerror(rc));
        ret = false;
        goto out_easy_cleanup;
    }

out_easy_cleanup:
    curl_easy_cleanup(curl);
out_global_cleanup:
    curl_global_cleanup();
out_memory:
    if (!ret && ctx.rsa_cert_buffer) {
      free(ctx.rsa_cert_buffer);
      ctx.rsa_cert_buffer = NULL;
      ctx.rsa_cert_buffer_size = 0;
      ctx.curl_buffer_size = 0;
    }
    free(weblink);

    return ret;
}

bool get_web_ek_certificate(void) {

    if (ctx.SSL_NO_VERIFY) {
        LOG_WARN("TLS communication with the said TPM manufacturer server setup"
                 " with SSL_NO_VERIFY!");
    }

    bool ret = true;
    char *ek_uri = encode_ek_public();
    if (!ek_uri) {
        LOG_ERR("Failed to encode EK.");
        ret = false;
        goto out;
    }

    LOG_INFO("%s", ek_uri);

    ctx.ek_server_addr = get_ek_server_address();
    if (!ctx.ek_server_addr) {
        LOG_ERR("Please specify an EK server address on the command line.");
        ret = false;
        goto out;
    }

    ret = retrieve_web_endorsement_certificate(ek_uri);

    free(ek_uri);
out:
    return ret;
}

tool_rc get_tpm_properties(ESYS_CONTEXT *ectx) {

    TPMI_YES_NO more_data;
    TPMS_CAPABILITY_DATA *capability_data;
    tool_rc rc = tool_rc_success;
    rc = tpm2_getcap(ectx, TPM2_CAP_TPM_PROPERTIES, TPM2_PT_MANUFACTURER,
            1, &more_data, &capability_data);
    if (rc != tool_rc_success) {
        LOG_ERR("TPM property read failure.");
        goto get_tpm_properties_out;
    }

    ctx.manufacturer = capability_data->data.tpmProperties.tpmProperty[0].value;

    if (ctx.manufacturer == VENDOR_IBMSIM) {
        LOG_WARN("The TPM device is a simulator —— Inspect the certficate chain and root certificate");
    }

    free(capability_data);
    rc = tpm2_getcap(ectx, TPM2_CAP_TPM_PROPERTIES, TPM2_PT_PERMANENT,
            1, &more_data, &capability_data);
    if (rc != tool_rc_success) {
        LOG_ERR("TPM property read failure.");
        goto get_tpm_properties_out;
    }

    if (capability_data->data.tpmProperties.tpmProperty[0].value &
        TPMA_PERMANENT_TPMGENERATEDEPS) {
            ctx.is_tpmgeneratedeps = true;
    }

    free(capability_data);
    rc = tpm2_getcap(ectx, TPM2_CAP_HANDLES,
        tpm2_util_hton_32(TPM2_HT_NV_INDEX), TPM2_PT_NV_INDEX_MAX, NULL,
        &capability_data);
    if (rc != tool_rc_success) {
        LOG_ERR("Failed to read capability data for NV indices.");
        ctx.is_cert_on_nv = false;
        goto get_tpm_properties_out;
    }

    if (capability_data->data.handles.count == 0) {
        ctx.is_cert_on_nv = false;
        goto get_tpm_properties_out;
    }

    UINT32 i;
    for (i = 0; i < capability_data->data.handles.count; i++) {
        TPMI_RH_NV_INDEX index = capability_data->data.handles.handle[i];
        if (index == RSA_EK_CERT_NV_INDEX) {
            ctx.is_rsa_ek_cert_nv_location_defined = true;
        }
        if (index == ECC_EK_CERT_NV_INDEX) {
            ctx.is_ecc_ek_cert_nv_location_defined = true;
        }
    }

    if (!ctx.is_rsa_ek_cert_nv_location_defined &&
    !ctx.is_ecc_ek_cert_nv_location_defined) {
        ctx.is_cert_on_nv = false;
    }

get_tpm_properties_out:
    free(capability_data);
    return rc;
}

tool_rc nv_read(ESYS_CONTEXT *ectx, TPMI_RH_NV_INDEX nv_index) {

    /*
     * Typical NV Index holding EK certificate has an empty auth
     * with attributes:
     * ppwrite|ppread|ownerread|authread|no_da|written|platformcreate
     */
    const bool is_rsa = nv_index == RSA_EK_CERT_NV_INDEX;
    char index_string[11];
    if (is_rsa) {
        strcpy(index_string, "0x01C00002");
    } else {
        strcpy(index_string, "0x01C0000A");
    }
    tpm2_loaded_object object;
    tool_rc tmp_rc = tool_rc_success;
    tool_rc rc = tpm2_util_object_load_auth(ectx, index_string, NULL, &object,
        false, TPM2_HANDLE_FLAGS_NV);
    if (rc != tool_rc_success) {
        goto nv_read_out;
    }

    TPM2B_DIGEST cp_hash = { 0 };
    TPM2B_DIGEST rp_hash = { 0 };
    uint16_t nv_buf_size = 0;
    rc = is_rsa ?
         tpm2_util_nv_read(ectx, nv_index, 0, 0, &object, &ctx.rsa_cert_buffer,
            &nv_buf_size, &cp_hash, &rp_hash, TPM2_ALG_SHA256, 0,
            ESYS_TR_NONE, ESYS_TR_NONE, NULL) :

         tpm2_util_nv_read(ectx, nv_index, 0, 0, &object, &ctx.ecc_cert_buffer,
            &nv_buf_size, &cp_hash, &rp_hash, TPM2_ALG_SHA256, 0,
            ESYS_TR_NONE, ESYS_TR_NONE, NULL);
    if (is_rsa) {
        ctx.rsa_cert_buffer_size = nv_buf_size;
    } else {
        ctx.ecc_cert_buffer_size = nv_buf_size;
    }

nv_read_out:
    tmp_rc = tpm2_session_close(&object.session);
    if (rc != tool_rc_success) {
        return tmp_rc;
    }

    return rc;
}

tool_rc get_nv_ek_certificate(ESYS_CONTEXT *ectx) {

    if (!ctx.is_cert_on_nv) {
        LOG_ERR("TCG specified location for EK certs aren't defined.");
        return tool_rc_general_error;
    }

    if (ctx.SSL_NO_VERIFY) {
        LOG_WARN("Ignoring -X or --allow-unverified if EK certificate found on NV");
    }

    if (ctx.ek_path) {
        LOG_WARN("Ignoring -u or --ek-public option if EK certificate found on NV");
        return tool_rc_option_error;
    }

    if (ctx.is_rsa_ek_cert_nv_location_defined &&
    ctx.is_ecc_ek_cert_nv_location_defined && ctx.cert_count == 1) {
        LOG_WARN("Found 2 certficates on NV. Add another -o to save the ECC cert");
    }

    if ((!ctx.is_rsa_ek_cert_nv_location_defined ||
    !ctx.is_ecc_ek_cert_nv_location_defined) && ctx.cert_count == 2) {
        LOG_WARN("Ignoring the additional output file since only 1 cert found on NV");
    }

    tool_rc rc = tool_rc_success;
    if (ctx.is_rsa_ek_cert_nv_location_defined) {
        rc = nv_read(ectx, RSA_EK_CERT_NV_INDEX);
        if (rc != tool_rc_success) {
            return rc;
        }
    }

    if (ctx.is_ecc_ek_cert_nv_location_defined) {
        rc = nv_read(ectx, ECC_EK_CERT_NV_INDEX);
    }

    return rc;
}

tool_rc print_intel_ek_certificate_warning(void) {

    if (ctx.manufacturer == VENDOR_INTEL &&
    ctx.is_tpmgeneratedeps && !ctx.is_cert_on_nv) {

        LOG_ERR("Cannot proceed. For further information please refer to: "
                "https://www.intel.com/content/www/us/en/security-center/"
                "advisory/intel-sa-00086.html. Recovery tools are located here:"
                "https://github.com/intel/INTEL-SA-00086-Linux-Recovery-Tools");

        return tool_rc_general_error;
    }

    return tool_rc_success;
}

tool_rc get_ek_certificates(ESYS_CONTEXT *ectx, struct attester_conf *conf) {

    /* if (!ctx.ek_path && !ctx.is_cert_on_nv) {
        LOG_ERR("Must specify the EK public key path");
        return tool_rc_option_error;
    } */

    if (!ctx.ek_server_addr && !ctx.is_cert_on_nv) {
        LOG_ERR("Must specify a valid remote server url!");
        return tool_rc_option_error;
    }

    tool_rc rc = tool_rc_success;
    if (ctx.is_tpm2_device_active) {
        rc = get_tpm_properties(ectx);
        if (rc != tool_rc_success) {
            LOG_ERR("Could not load TPM properties");
            return rc;
        }
    }

    /* read ecc certificate if present */
    if (ctx.ec_cert_path_2 && ctx.is_ecc_ek_cert_nv_location_defined) {
        /* if (!access(conf->ek_ecc_cert, F_OK)) {
            // file doesn't exist
        } */
        ctx.ec_cert_file_handle_2 = fopen(conf->ek_ecc_cert, "wb");
        fprintf(stdout, "INFO: creating file to store ECC EK certifcate\n");
        if (!ctx.ec_cert_file_handle_2) {
            LOG_ERR("Could not open file for writing: \"%s\"",
                conf->ek_ecc_cert);
            return tool_rc_general_error;
        }
    }
    else {
        /* read rsa certificate if the ecc one is not present */
        if (ctx.ec_cert_path_1) {
            /* if (!access(conf->ek_rsa_cert, F_OK)) {
                // file doesn't exist
            } */
            ctx.ec_cert_file_handle_1 = fopen(conf->ek_rsa_cert, "wb");
            fprintf(stdout, "INFO: creating file to store RSA EK certifcate\n");
            if (!ctx.ec_cert_file_handle_1) {
                LOG_ERR("Could not open file for writing: \"%s\"",
                    conf->ek_rsa_cert);
                return tool_rc_general_error;
            }
        }
    }

    if (ctx.ek_path) {
        ctx.out_public = malloc(sizeof(*ctx.out_public));
        ctx.out_public->size = 0;
        bool res = files_load_public(ctx.ek_path, ctx.out_public);
        if (!res) {
            LOG_ERR("Could not load EK public from file");
            return tool_rc_general_error;
        }
    }

    rc = print_intel_ek_certificate_warning();
    if (rc != tool_rc_success) {
        LOG_ERR("error in print_intel_ek_warning");
        return rc;
    }

    if (ctx.is_cert_on_nv) {
        rc = get_nv_ek_certificate(ectx);
        if (rc != tool_rc_success) {
            LOG_WARN("EK certificate not found on NV");
            ctx.is_cert_on_nv = false;
        }
    }

    /*
     * Following is everything applicable to ctx.is_cert_on_nv = false.
     */
    if(!ctx.is_cert_on_nv){
        if (!ctx.ek_path) {
            LOG_ERR("Must specify the EK public key path");
            return tool_rc_option_error;
        }

        if (ctx.cert_count > 1) {
            LOG_ERR("Specify one output path for EK cert file per EK public key");
            return tool_rc_option_error;
        }

        bool retval = get_web_ek_certificate();
        if (!retval) {
            return tool_rc_general_error;
        }
    }

    rc = save_cert(conf);
    if(rc != tool_rc_success){
        LOG_ERR("Could not save certificates on file");
        return tool_rc_general_error;
    }

    rc = free_ctx();
    if(rc != tool_rc_success){
        LOG_ERR("Could not correctly free the context");
        return tool_rc_general_error;
    }

    return tool_rc_success;
}

char *base64_decode(char **split, unsigned int cert_length) {

    *split += strlen("certficate\" : ");
    char *final_string = NULL;
    int outlen;
    CURL *curl = curl_easy_init();
    if (curl) {
        char *output = curl_easy_unescape(curl, *split, cert_length, &outlen);
        if (output) {
            final_string = strdup(output);
            curl_free(output);
        }
    }
    curl_easy_cleanup(curl);
    curl_global_cleanup();

    if(final_string) {
        size_t i;
        for (i = 0; i < strlen(final_string); i++) {
            final_string[i] = final_string[i] == '-' ? '+'  : final_string[i];
            final_string[i] = final_string[i] == '_' ? '/'  : final_string[i];
            final_string[i] = final_string[i] == '"' ? '\0' : final_string[i];
            final_string[i] = final_string[i] == '}' ? '\0' : final_string[i];
        }
    }

    return final_string;
}

unsigned char check_ek_cert_algo(ESYS_CONTEXT *ectx){
    //TPMI_YES_NO more_data;
    TPMS_CAPABILITY_DATA *capability_data;
    tool_rc rc = tool_rc_success;
    unsigned char ret = ERR_CHECK;

    rc = tpm2_getcap(ectx, TPM2_CAP_HANDLES,
        tpm2_util_hton_32(TPM2_HT_NV_INDEX), TPM2_PT_NV_INDEX_MAX, NULL,
        &capability_data);
    if (rc != tool_rc_success) {
        LOG_ERR("Failed to read capability data for NV indices.");
        goto func_out;
    }

    if (capability_data->data.handles.count == 0) {
        ret = NO_CERT_CHECK;
        goto func_out;
    }

    UINT32 i;
    for (i = 0; i < capability_data->data.handles.count; i++) {
        TPMI_RH_NV_INDEX index = capability_data->data.handles.handle[i];
        if (index == RSA_EK_CERT_NV_INDEX) {
            if(ret == ECC_CHECK){
                ret = ECC_AND_RSA_CHECK;
            }
            else {
                ret = RSA_CHECK;
            }
        }
        if (index == ECC_EK_CERT_NV_INDEX) {
            if(ret == RSA_CHECK){
                ret = ECC_AND_RSA_CHECK;
            }
            else {
                ret = ECC_CHECK;
            }
        }
    }

func_out:
    free(capability_data);
    return ret;
}
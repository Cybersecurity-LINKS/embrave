#ifndef __EK_CERT___
#define __EK_CERT___

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <curl/curl.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include "files.h"
#include "log.h"
#include "object.h"
#include "tpm2.h"
#include "tpm2_alg_util.h"
#include "tpm2_auth_util.h"
#include "tpm2_capability.h"
#include "tpm2_nv_util.h"
#include "tpm2_tool.h"

typedef enum pubkey_enc_mode pubkey_enc_mode;
enum pubkey_enc_mode {
    ENC_AUTO = 0,
    ENC_INTEL = 1,
    ENC_AMD = 2,
};

typedef enum tpm_manufacturer tpm_manufacturer;
enum tpm_manufacturer {
    VENDOR_AMD       = 0x414D4400,
    VENDOR_ATMEL     = 0x41544D4C,
    VENDOR_BROADCOM  = 0x4252434D,
    VENDOR_CISCO     = 0x4353434F,
    VENDOR_FLYSLICE  = 0x464C5953,
    VENDOR_ROCKCHIP  = 0x524F4343,
    VENDOR_GOOGLE    = 0x474F4F47,
    VENDOR_HPE       = 0x48504500,
    VENDOR_HUAWEI    = 0x48495349,
    VENDOR_IBM       = 0x49424D00,
    VENDOR_IBMSIM    = 0x49424D20, // Used only by mssim/ibmswtpm2
    VENDOR_INFINEON  = 0x49465800,
    VENDOR_INTEL     = 0x494E5443,
    VENDOR_LENOVO    = 0x4C454E00,
    VENDOR_MICROSOFT = 0x4D534654,
    VENDOR_NSM       = 0x4E534D20,
    VENDOR_NATIONZ   = 0x4E545A00,
    VENDOR_NUVOTON   = 0x4E544300,
    VENDOR_QUALCOMM  = 0x51434F4D,
    VENDOR_SAMSUNG   = 0x534D534E,
    VENDOR_SINOSUN   = 0x534E5300,
    VENDOR_SMSC      = 0x534D5343,
    VENDOR_STM       = 0x53544D20,
    VENDOR_TXN       = 0x54584E00,
    VENDOR_WINBOND   = 0x57454300,
};

typedef struct tpm_getekcertificate_ctx tpm_getekcertificate_ctx;
struct tpm_getekcertificate_ctx {
    // TPM Device properties
    bool is_tpm2_device_active;
    bool is_cert_on_nv;
    tpm_manufacturer manufacturer;
    bool is_rsa_ek_cert_nv_location_defined;
    bool is_ecc_ek_cert_nv_location_defined;
    bool is_tpmgeneratedeps;
    // Certficate data handling
    uint8_t cert_count;
    //char *ec_cert_path_1;
    FILE *ec_cert_file_handle_1;
    //char *ec_cert_path_2;
    //FILE *ec_cert_file_handle_2;
    unsigned char *rsa_cert_buffer;
    size_t rsa_cert_buffer_size;
    unsigned char *ecc_cert_buffer;
    size_t ecc_cert_buffer_size;
    bool is_cert_raw;
    size_t curl_buffer_size;
    // EK certificate hosting particulars
    char *ek_server_addr;
    unsigned int SSL_NO_VERIFY;
    char *ek_path;
    pubkey_enc_mode encoding;
    bool verbose;
    TPM2B_PUBLIC *out_public;
};

typedef enum ek_nv_index ek_nv_index;
enum ek_nv_index {
    RSA_EK_CERT_NV_INDEX = 0x01C00002,
    ECC_EK_CERT_NV_INDEX = 0x01C0000A
};

bool retrieve_ek_cert(ESYS_CONTEXT *ectx, char * ek_cert_path);

#endif
// Copyright (C) 2023 Fondazione LINKS 

// This program is free software; you can redistribute it and/or modify 
// it under the terms of the GNU General Public License as published by the Free Software Foundation; version 2.

// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
// See the GNU General Public License for more details.

// You should have received a copy of the GNU General Public License along with this program; if not, 
// write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

#ifndef __CONFIG_PARSE___
#define __CONFIG_PARSE___

#include <stdint.h>
#include <errno.h>

#define CONFIG_FILE_PATH "/home/linux/Documents/lemon/lemon.conf"  /* development path */
#define MAX_BUF 255
#define MAX_LINE_LENGTH 1023
#define ATTESTER_NUM_CONFIG_PARAMS 12
#define VERIFIER_NUM_CONFIG_PARAMS 7
#define JOIN_SERVICE_NUM_CONFIG_PARAMS 8

enum attester_keys_config{
    ATTESTER_IP,
    ATTESTER_PORT,
    ATTESTER_TLS_PORT,
    ATTESTER_TLS_CERT,
    ATTESTER_TLS_KEY,
    ATTESTER_EK_RSA_CERT,
    ATTESTER_EK_ECC_CERT,
    ATTESTER_AK_PUB,
    ATTESTER_AK_NAME,
    ATTESTER_AK_CTX,
    ATTESTER_AK_CERT,
    ATTESTER_JOIN_SERVICE_IP
};
enum verifier_keys_config{
    VERIFIER_IP,
    VERIFIER_PORT,
    VERIFIER_TLS_PORT,
    VERIFIER_TLS_CERT,
    VERIFIER_TLS_KEY,
    VERIFIER_TLS_CERT_CA,
    VERIFIER_DB
};
enum join_service_keys_config{
    JOIN_SERVICE_IP,
    JOIN_SERVICE_PORT,
    JOIN_SERVICE_TLS_PORT,
    JOIN_SERVICE_TLS_CERT,
    JOIN_SERVICE_TLS_KEY,
    JOIN_SERVICE_TLS_CERT_CA,
    JOIN_SERVICE_DB,
    JOIN_SERVICE_CA_IP
};

struct attester_conf {
    uint32_t port;
    uint32_t tls_port;
    char ip[MAX_BUF];
    char tls_cert[MAX_LINE_LENGTH];
    char tls_key[MAX_LINE_LENGTH];
    char ek_rsa_cert[MAX_BUF];
    char ek_ecc_cert[MAX_BUF];
    char ak_pub[MAX_BUF];
    char ak_name[MAX_BUF];
    char ak_ctx[MAX_BUF];
    char ak_cert[MAX_BUF];
    char join_service_ip[MAX_BUF];
};

struct verifier_conf {
    char db[MAX_LINE_LENGTH];
    uint32_t port;
    uint32_t tls_port;
    char ip[MAX_BUF];
    char tls_cert_ca[MAX_LINE_LENGTH];
    char tls_cert[MAX_LINE_LENGTH];
    char tls_key[MAX_LINE_LENGTH];
};

struct join_service_conf {
    char db[MAX_LINE_LENGTH];
    uint32_t port;
    uint32_t tls_port;
    char ip[MAX_BUF];
    char tls_cert_ca[MAX_LINE_LENGTH];
    char tls_cert[MAX_LINE_LENGTH];
    char tls_key[MAX_LINE_LENGTH];
};

enum attester_keys_config attester_parse_key(char* key);
enum verifier_keys_config verifier_parse_key(char* key);
uint16_t read_config(char user, void* config_struct);

#endif
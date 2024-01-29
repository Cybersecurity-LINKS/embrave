// Copyright (C) 2023 Fondazione LINKS 

// This program is free software; you can redistribute it and/or modify 
// it under the terms of the GNU General Public License as published by the Free Software Foundation; version 2.

// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
// See the GNU General Public License for more details.

// You should have received a copy of the GNU General Public License along with this program; if not, 
// write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config_parse.h"

char* attester_params[ATTESTER_NUM_CONFIG_PARAMS] = {"uuid", "ip", "port", "tls_port", "tls_cert", "tls_key",
            "ek_rsa_cert", "ek_ecc_cert", "ak_pub", "ak_name", "ak_ctx", "ak_cert", "join_service_ip"};
char* verifier_params[VERIFIER_NUM_CONFIG_PARAMS] = {"ip", "port", "tls_port", "tls_cert", "tls_key",
            "tls_cert_ca", "db"};
char* join_service_params[JOIN_SERVICE_NUM_CONFIG_PARAMS] = {"ip", "port", "tls_port", "tls_cert",
            "tls_key", "tls_cert_ca", "db", "ca_ip"};

enum attester_keys_config attester_parse_key(char* key){
    int i = 0;

    for(i=0; i<ATTESTER_NUM_CONFIG_PARAMS; i++){
        if(!strcmp(key, attester_params[i]))
            return (enum attester_keys_config) i;
    }

    return (enum attester_keys_config) i;
}

enum verifier_keys_config verifier_parse_key(char* key){
    int i = 0;

    for(i=0; i<VERIFIER_NUM_CONFIG_PARAMS; i++){
        if(!strcmp(key, verifier_params[i]))
            return (enum verifier_keys_config) i;
    }

    return (enum verifier_keys_config) i;
}

enum join_service_keys_config join_service_parse_key(char* key){
    int i = 0;

    for(i=0; i<JOIN_SERVICE_NUM_CONFIG_PARAMS; i++){
        if(!strcmp(key, join_service_params[i]))
            return (enum join_service_keys_config) i;
    }

    return (enum join_service_keys_config) i;
}

/*
user: 
        - 0: attester
        - 1: verifier
        - 2: join_service
*/
uint16_t read_config(char user, void* config_struct){
    FILE* fd;
    char key[MAX_BUF], value[MAX_BUF];
    char line[MAX_LINE_LENGTH + 1];
    struct attester_conf* attester_config = NULL;
    struct verifier_conf* verifier_config = NULL;
    struct join_service_conf* join_service_config = NULL;

    if(user != 0 && user != 1 && user != 2 ){
        fprintf(stderr, "ERROR: unknown config user\n");
        errno = 5;
        return (uint16_t) -1;
    }
    
    if(config_struct == NULL){
        fprintf(stderr, "ERROR: config_struct is NULL\n");
        errno = 4;
        return (uint16_t) -1;
    }

    fd = fopen(CONFIG_FILE_PATH, "r");
    if(fd == NULL){
        fprintf(stderr, "ERROR: failed to open config file\n");
        errno = 3;
        return (uint16_t) -1;
    }

    /* select which component needs the configuration */
    switch (user)
    {
    case 0:
        attester_config = (struct attester_conf*) config_struct;
        break;

    case 1:
        verifier_config = (struct verifier_conf*) config_struct;
        break;

    case 2:
        join_service_config = (struct join_service_conf*) config_struct;
        break;

    default:
        break;
    }

    while(fgets(line, MAX_LINE_LENGTH, fd)){
        /* comment or new line found */
        if(line[0] == '#' || line[0] == '\n')
            continue;

        /* read section header of the config file */
        if(line[0] == '['){
            char section[MAX_LINE_LENGTH];
            char* c = line;
            int i = 0;
            for(i = 0; *c != ']'; c++){
                if(*c == '[')
                    continue;

                section[i] = *c;
                i++;                
            }
            section[i] = '\0';

            /* AttesterAgent section management */
            if(user == 0 && !strcmp(section, "AttesterAgent")){
                while(fgets(line, MAX_LINE_LENGTH, fd)){
                    /* comment or new line found */
                    if(line[0] == '#' || line[0] == '\n')
                        continue;

                    if(line[0] == '['){
                        break;
                    }

                    sscanf(line, "%s = %s", key, value);

                    enum attester_keys_config param = attester_parse_key(key);

                    switch((int) param){
                        case ATTESTER_UUID:
                            strcpy(attester_config->uuid, value);
                            break;

                        case ATTESTER_IP:
                            strcpy(attester_config->ip, value);
                            break;

                        case ATTESTER_PORT:
                            attester_config->port = (uint32_t) atoi(value);
                            break;

                        case ATTESTER_TLS_PORT:
                            attester_config->tls_port = (uint32_t) atoi(value);
                            break;

                        case ATTESTER_TLS_CERT:
                            strcpy(attester_config->tls_cert, value);
                            break;

                        case ATTESTER_TLS_KEY:
                            strcpy(attester_config->tls_key, value);
                            break;

                        case ATTESTER_EK_RSA_CERT:
                            strcpy(attester_config->ek_rsa_cert, value);
                            break;

                        case ATTESTER_EK_ECC_CERT:
                            strcpy(attester_config->ek_ecc_cert, value);
                            break;

                        case ATTESTER_AK_PUB:
                            strcpy(attester_config->ak_pub, value);
                            break;

                        case ATTESTER_AK_NAME:
                            strcpy(attester_config->ak_name, value);
                            break;
                        
                        case ATTESTER_AK_CTX:
                            strcpy(attester_config->ak_ctx, value);
                            break;

                        case ATTESTER_AK_CERT:
                            strcpy(attester_config->ak_cert, value);
                            break;

                        case ATTESTER_JOIN_SERVICE_IP:
                            strcpy(attester_config->join_service_ip, value);
                            break;

                        case ATTESTER_NUM_CONFIG_PARAMS:
                            //unknown param
                            break;

                        default:
                            break;
                    }
                }
            }

            /* Verifier section management */
            if(user == 1 && !strcmp(section, "Verifier")){
                while(fgets(line, MAX_LINE_LENGTH, fd)){
                    /* comment or new line found */
                    if(line[0] == '#' || line[0] == '\n')
                        continue;

                    if(line[0] == '['){
                        break;
                    }

                    sscanf(line, "%s = %s", key, value);

                    enum verifier_keys_config param = verifier_parse_key(key);

                    switch((int) param){
                        case VERIFIER_IP:
                            strcpy(verifier_config->ip, value);
                            break;

                        case VERIFIER_PORT:
                            verifier_config->port = (uint32_t) atoi(value);
                            break;

                        case VERIFIER_TLS_PORT:
                            verifier_config->tls_port = (uint32_t) atoi(value);
                            break;

                        case VERIFIER_TLS_CERT:
                            strcpy(verifier_config->tls_cert, value);
                            break;

                        case VERIFIER_TLS_KEY:
                            strcpy(verifier_config->tls_key, value);
                            break;

                        case VERIFIER_TLS_CERT_CA:
                            strcpy(verifier_config->tls_cert_ca, value);
                            break;

                        case VERIFIER_DB:
                            strcpy(verifier_config->db, value);
                            break;

                        case VERIFIER_NUM_CONFIG_PARAMS:
                            //unknown param
                            break;

                        default:
                            break;
                    }
                }
            }

            /* Join Service section management */
            if(user == 2 && !strcmp(section, "JoinService")){
                while(fgets(line, MAX_LINE_LENGTH, fd)){
                    /* comment or new line found */
                    if(line[0] == '#' || line[0] == '\n')
                        continue;

                    if(line[0] == '['){
                        break;
                    }

                    sscanf(line, "%s = %s", key, value);

                    enum join_service_keys_config param = join_service_parse_key(key);

                    switch((int) param){
                        case JOIN_SERVICE_IP:
                            strcpy(join_service_config->ip, value);
                        break;
                        
                        case JOIN_SERVICE_PORT:
                            join_service_config->port = (uint32_t) atoi(value);
                            break;

                        case JOIN_SERVICE_TLS_PORT:
                            join_service_config->tls_port = (uint32_t) atoi(value);
                            break;

                        case JOIN_SERVICE_TLS_CERT:
                            strcpy(join_service_config->tls_cert, value);
                            break;

                        case JOIN_SERVICE_TLS_KEY:
                            strcpy(join_service_config->tls_key, value);
                            break;

                        case JOIN_SERVICE_TLS_CERT_CA:
                            strcpy(join_service_config->tls_cert_ca, value);
                            break;

                        case JOIN_SERVICE_DB:
                            strcpy(join_service_config->db, value);
                            break;

                        case JOIN_SERVICE_NUM_CONFIG_PARAMS:
                            //unknown param
                            break;

                        default:
                            break;
                    }
                }
            }
        }
    }

    return (uint16_t) 0;
}
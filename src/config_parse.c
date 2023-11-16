#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config_parse.h"

char* attester_params[ATTESTER_NUM_CONFIG_PARAMS] = {"ip", "port", "tls_port", "tls_cert", "tls_key"};
char* verifier_params[VERIFIER_NUM_CONFIG_PARAMS] = {"ip", "port", "tls_port", "tls_cert", "tls_key", "tls_cert_ca", "db"};

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

/*
user: 
        - 0: attester
        - 1: verifier
*/
uint16_t read_config(char user, void* config_struct){
    FILE* fd;
    char key[MAX_BUF], value[MAX_BUF];
    char line[MAX_LINE_LENGTH + 1];
    struct attester_conf* attester_config = NULL;
    struct verifier_conf* verifier_config = NULL;

    if(user != 0 && user != 1){
        fprintf(stderr, "ERROR: unknown user\n");
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

    if(user == 0){
        attester_config = (struct attester_conf*) config_struct;
    }
    if(user == 1){
        verifier_config = (struct verifier_conf*) config_struct;
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

                    switch(param){
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

                    switch(param){
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
        }
    }

    return (uint16_t) 0;
}
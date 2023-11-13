#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config_parse.h"

char* attester_params[ATTESTER_NUM_CONFIG_PARAMS] = {"ip", "port", "tls_port", "certs_dir"};
char* verifier_params[VERIFIER_NUM_CONFIG_PARAMS] = {"ip", "port", "tls_port", "certs_dir", "db"};

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
__uint16_t read_config(char user, void* config_struct){
    FILE* fd;
    char key[MAX_BUF], value[MAX_BUF];
    char line[MAX_LINE_LENGTH + 1];
    struct attester_conf* attester_config = NULL;
    struct verifier_conf* verifier_config = NULL;
    
    if(config_struct == NULL){
        fprintf(stderr, "ERROR: config_struct is NULL\n");
        exit(4);
    }

    fd = fopen(CONFIG_FILE_PATH, "r");
    if(fd == NULL){
        fprintf(stderr, "ERROR: failed to open config file\n");
        exit(3);
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
                            attester_config->port = (__uint32_t) atoi(value);
                            break;

                        case ATTESTER_TLS_PORT:
                            attester_config->tls_port = (__uint32_t) atoi(value);
                            break;

                        case ATTESTER_CERTS_DIR:
                            strcpy(attester_config->certs_dir, value);
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
                            verifier_config->port = (__uint32_t) atoi(value);
                            break;

                        case VERIFIER_TLS_PORT:
                            verifier_config->tls_port = (__uint32_t) atoi(value);
                            break;

                        case VERIFIER_CERTS_DIR:
                            strcpy(verifier_config->certs_dir, value);
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
}
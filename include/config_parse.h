#ifndef __CONFIG_PARSE___
#define __CONFIG_PARSE___

#include <stdint.h>
#include <errno.h>

#define CONFIG_FILE_PATH "/home/enrico/Documents/PoliTo/PhD/LINKS/lemon/lemon.conf"  /* development path */
#define MAX_BUF 255
#define MAX_LINE_LENGTH 1023
#define ATTESTER_NUM_CONFIG_PARAMS 5
#define VERIFIER_NUM_CONFIG_PARAMS 6

enum attester_keys_config{ATTESTER_IP, ATTESTER_PORT, ATTESTER_TLS_PORT, ATTESTER_TLS_CERT, ATTESTER_TLS_KEY};
enum verifier_keys_config{VERIFIER_IP, VERIFIER_PORT, VERIFIER_TLS_PORT, VERIFIER_TLS_CERT, VERIFIER_TLS_KEY, VERIFIER_DB};

struct attester_conf {
    uint32_t port;
    uint32_t tls_port;
    char ip[MAX_BUF];
    char tls_cert[MAX_LINE_LENGTH];
    char tls_key[MAX_LINE_LENGTH];
};

struct verifier_conf {
    char db[MAX_LINE_LENGTH];
    uint32_t port;
    uint32_t tls_port;
    char ip[MAX_BUF];
    char tls_cert[MAX_LINE_LENGTH];
    char tls_key[MAX_LINE_LENGTH];
};

enum attester_keys_config attester_parse_key(char* key);
enum verifier_keys_config verifier_parse_key(char* key);
uint16_t read_config(char user, void* config_struct);

#endif
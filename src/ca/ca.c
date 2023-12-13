// Copyright (C) 2023 Fondazione LINKS 

// This program is free software; you can redistribute it and/or modify 
// it under the terms of the GNU General Public License as published by the Free Software Foundation; version 2.

// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
// See the GNU General Public License for more details.

// You should have received a copy of the GNU General Public License along with this program; if not, 
// write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

#include "ca.h"
#include "config_parse.h"

static void fn(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *) ev_data;
        if (mg_http_match_uri(hm, API_REQUEST_CERTIFICATE)) {
            
        // Expecting JSON array in the HTTP body, e.g. [ 123.38, -2.72 ]
        double num1, num2;
        if (mg_json_get_num(hm->body, "$[0]", &num1) &&
            mg_json_get_num(hm->body, "$[1]", &num2)) {
            // Success! create JSON response
            mg_http_reply(c, OK, APPLICATION_JSON,
                        "{%m:%g}\n",
                        mg_print_esc, 0, "result", num1 + num2);
            MG_INFO(("%s %s %d", GET, API_REQUEST_CERTIFICATE, OK));
        } else {
            mg_http_reply(c, 500, NULL, "Parameters missing\n");
        }
        } else {
        mg_http_reply(c, 500, NULL, "\n");
        }
    }
}

/* static void hello_world(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
    if (ev == MG_EV_HTTP_MSG) {
        mg_http_reply(c, 200, "Content-Type: text/plain\r\n", "Hello, %s\n", "world");
    }
} */

int main(int argc, char *argv[]) {
    struct mg_mgr mgr;
    struct mg_connection *c;
    mg_mgr_init(&mgr);
    struct ca_conf ca_config;

    /* read configuration from cong file */
    if(read_config(/* ca */ 2, (void * ) &ca_config)){
        int err = errno;
        fprintf(stderr, "ERROR: could not read configuration file\n");
        exit(err);
    }
    #define VERBOSE
    #ifdef  VERBOSE
    printf("ca_config->ip: %s\n", ca_config.ip);
    printf("ca_config->port: %d\n", ca_config.port);
    printf("ca_config->tls_port: %d\n", ca_config.tls_port);
    printf("ca_config->tls_cert: %s\n", ca_config.tls_cert);
    printf("ca_config->tls_key: %s\n", ca_config.tls_key);
    printf("ca_config->db: %s\n", ca_config.db);
    #endif
                                          // Init manager
    if((c = mg_http_listen(&mgr, "http://localhost:8000", fn, &mgr)) == NULL){  // Setup listener
        MG_ERROR(("Cannot listen on http://localhost:8000"));
        exit(EXIT_FAILURE);
    }

    for (;;) mg_mgr_poll(&mgr, 1000);                         // Event loop
    mg_mgr_free(&mgr);                                        // Cleanup
    return 0;
}
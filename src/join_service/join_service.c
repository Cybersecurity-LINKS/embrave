// Copyright (C) 2023 Fondazione LINKS 

// This program is free software; you can redistribute it and/or modify 
// it under the terms of the GNU General Public License as published by the Free Software Foundation; version 2.

// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
// See the GNU General Public License for more details.

// You should have received a copy of the GNU General Public License along with this program; if not, 
// write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

#include "join_service.h"
#include "config_parse.h"

static struct join_service_conf js_config;

static void fn(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *) ev_data;
        if (mg_http_match_uri(hm, API_JOIN)) {
            mg_http_reply(c, OK, APPLICATION_JSON,
                        "{\"%s\":\"%s\"}",
                        "ca_ip_addr", js_config.ca_ip);
            MG_INFO(("%s %s %d", GET, API_JOIN, OK));
        }
        // Expecting JSON array in the HTTP body, e.g. [ 123.38, -2.72 ]
        //double num1, num2;
        //if (mg_json_get_num(hm->body, "$[0]", &num1) &&
        //    mg_json_get_num(hm->body, "$[1]", &num2)) {
            // Success! create JSON response
        //    mg_http_reply(c, OK, APPLICATION_JSON,
        //                "{%m:%g}\n",
        //                mg_print_esc, 0, "result", num1 + num2);
        //    MG_INFO(("%s %s %d", GET, API_JOIN, OK));
        //} else {
        //    mg_http_reply(c, 500, NULL, "Parameters missing\n");
        //}
        else {
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
    char url[MAX_BUF];

    /* read configuration from cong file */
    if(read_config(/* join_service */ 3, (void * ) &js_config)){
        int err = errno;
        fprintf(stderr, "ERROR: could not read configuration file\n");
        exit(err);
    }
    
    #ifdef DEBUG
    printf("join_service_config->ip: %s\n", js_config.ip);
    printf("join_service_config->port: %d\n", js_config.port);
    printf("join_service_config->tls_port: %d\n", js_config.tls_port);
    printf("join_service_config->tls_cert: %s\n", js_config.tls_cert);
    printf("join_service_config->tls_key: %s\n", js_config.tls_key);
    printf("join_service_config->db: %s\n", js_config.db);
    printf("join_service_config->ca_ip: %s\n", js_config.ca_ip);
    #endif

    snprintf(url, 1024, "http://%s:%d", js_config.ip, js_config.port);
                                          // Init manager
    if((c = mg_http_listen(&mgr, url, fn, &mgr)) == NULL){  // Setup listener
        MG_ERROR(("Cannot listen on http://%s:%d", js_config.ip, js_config.port));
        exit(EXIT_FAILURE);
    }

    MG_INFO(("Listening on http://%s:%d", js_config.ip, js_config.port));

    for (;;) mg_mgr_poll(&mgr, 1000);                         // Event loop
    mg_mgr_free(&mgr);                                        // Cleanup
    return 0;
}
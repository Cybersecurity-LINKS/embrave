#include "join_service.h"
#include "config_parse.h"

static void fn(struct mg_connection *c, int ev, void *ev_data, void *fn_data) {
    if (ev == MG_EV_HTTP_MSG) {
        struct mg_http_message *hm = (struct mg_http_message *) ev_data;
        if (mg_http_match_uri(hm, API_JOIN)) {
            mg_http_reply(c, OK, APPLICATION_JSON,
                        "{\"%s\":\"%s\"}",
                        "ca_ip_addr", "localhost");
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

    /* read configuration from cong file */
    //if(read_config(/* join_service */ 1, (void * ) &verifier_config)){
    //    int err = errno;
    //    fprintf(stderr, "ERROR: could not read configuration file\n");
    //    exit(err);
    //}
                                          // Init manager
    if((c = mg_http_listen(&mgr, "http://localhost:8000", fn, &mgr)) == NULL){  // Setup listener
        MG_ERROR(("Cannot listen on http://localhost:8000"));
        exit(EXIT_FAILURE);
    }

    MG_INFO(("Listening on http://localhost:8000"));

    for (;;) mg_mgr_poll(&mgr, 1000);                         // Event loop
    mg_mgr_free(&mgr);                                        // Cleanup
    return 0;
}
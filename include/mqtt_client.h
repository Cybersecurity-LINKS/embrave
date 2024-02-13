#ifndef __MQTT_CLIENT__
#define __MQTT_CLIENT__

#include "mongoose.h"

/* const char *attester_topic_prefix = "attest/";
const char *verifiers_topic = "verfier/+";
const char *s_pub_topic = "mg/clnt/test"; */

#define ATTESTER_TOPIC_PREFIX = "attest/"
#define VERIFIERS_TOPIC = "verfier/+"

void mqtt_publish(struct mg_connection *c, char *topic, char *message);
void mqtt_subscribe(struct mg_connection *c, char *topic);
struct mg_connection *mqtt_connect(struct mg_mgr *mgr, mg_event_handler_t fn);
void timer_fn(void *arg);

#endif
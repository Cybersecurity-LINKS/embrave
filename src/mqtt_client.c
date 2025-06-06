// Copyright (C) 2024 Fondazione LINKS 

// This program is free software; you can redistribute it and/or modify 
// it under the terms of the GNU General Public License as published by the Free Software Foundation; version 2.

// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
// See the GNU General Public License for more details.

// You should have received a copy of the GNU General Public License along with this program; if not, 
// write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

#include "mqtt_client.h"
#include "mongoose.h"

static int s_qos = 1;                             // MQTT QoS

// Handle interrupts, like Ctrl-

// Timer function - recreate client connection if it is closed
struct mg_connection *mqtt_connect(struct mg_mgr *mgr, mg_event_handler_t fn, char *client_name, char * s_url) {
  struct mg_connection *conn;

  struct mg_mqtt_opts opts = {.client_id = mg_str(client_name)};
  conn = mg_mqtt_connect(mgr, s_url, &opts, fn, NULL);

  return conn;
}

void mqtt_publish(struct mg_connection *c, char *topic, char *message){
  struct mg_mqtt_opts pub_opts;
  struct mg_str pubt = mg_str(topic), data = mg_str(message);

  memset(&pub_opts, 0, sizeof(pub_opts));
  pub_opts.topic = pubt;
  pub_opts.message = data;
  pub_opts.qos = s_qos, pub_opts.retain = false;
  mg_mqtt_pub(c, &pub_opts);
#ifdef DEBUG
  MG_INFO(("%lu PUBLISHED %.*s -> %.*s", c->id, (int) data.len, data.ptr,
            (int) pubt.len, pubt.ptr));
#endif
}

void mqtt_subscribe(struct mg_connection *c, char *topic){
  struct mg_str subt = mg_str(topic);

  struct mg_mqtt_opts sub_opts;
  memset(&sub_opts, 0, sizeof(sub_opts));
  sub_opts.topic = subt;
  sub_opts.qos = s_qos;
  mg_mqtt_sub(c, &sub_opts);
  //MG_INFO(("%lu SUBSCRIBED to %.*s", c->id, (int) subt.len, subt.ptr));
  fprintf(stdout, "[Init] SUBSCRIBED to %.*s\n", (int) subt.len, subt.ptr);
}

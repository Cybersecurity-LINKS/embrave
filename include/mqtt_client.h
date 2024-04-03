// Copyright (C) 2024 Fondazione LINKS 

// This program is free software; you can redistribute it and/or modify 
// it under the terms of the GNU General Public License as published by the Free Software Foundation; version 2.

// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; 
// without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. 
// See the GNU General Public License for more details.

// You should have received a copy of the GNU General Public License along with this program; if not, 
// write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

#ifndef __MQTT_CLIENT__
#define __MQTT_CLIENT__

#include "mongoose.h"

#define ATTEST_TOPIC_PREFIX "attest/"
#define STATUS_TOPIC_PREFIX "status/"

void mqtt_publish(struct mg_connection *c, char *topic, char *message);
void mqtt_subscribe(struct mg_connection *c, char *topic);
struct mg_connection *mqtt_connect(struct mg_mgr *mgr, mg_event_handler_t fn, char *client_name, char * s_url);
#endif
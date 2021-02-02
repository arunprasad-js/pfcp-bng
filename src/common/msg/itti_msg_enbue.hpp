/* Copyright (c) 2020 Altran
 * Licensed to the OpenAirInterface (OAI) Software Alliance under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The OpenAirInterface Software Alliance licenses this file to You under
 * the OAI Public License, Version 1.1  (the "License"); you may not use this file
 * except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.openairinterface.org/?page_id=698
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *-------------------------------------------------------------------------------
 * For more information about the OpenAirInterface (OAI) Software Alliance:
 *      contact@openairinterface.org
 */

#ifndef ITTI_MSG_ENBUE_HPP_INCLUDED_
#define ITTI_MSG_ENBUE_HPP_INCLUDED_

#include "itti_msg.hpp"

#define MAX_NAI_LEN 150

class itti_enbue_msg : public itti_msg {
public:
  itti_enbue_msg(const itti_msg_type_t  msg_type, const task_id_t origin, const task_id_t destination):
    itti_msg(msg_type, origin, destination) {
    memset (&nai_userid, 0, MAX_NAI_LEN);
  }
  itti_enbue_msg(const itti_enbue_msg& i, const task_id_t orig, const task_id_t dest) : itti_enbue_msg(i)  {
    origin = orig;
    destination = dest;
  }
  char     nai_userid[MAX_NAI_LEN];
};

//-----------------------------------------------------------------------------
class itti_enbue_register_request : public itti_enbue_msg {
public:
  itti_enbue_register_request(const task_id_t origin, const task_id_t destination):
    itti_enbue_msg(ENBUE_REGISTER_REQUEST, origin, destination) {  }

  const char* get_msg_name() {return typeid(itti_enbue_register_request).name();};

};

//-----------------------------------------------------------------------------
class itti_enbue_deregister_request : public itti_enbue_msg {
public:
  itti_enbue_deregister_request(const task_id_t origin, const task_id_t destination):
    itti_enbue_msg(ENBUE_DEREGISTER_REQUEST, origin, destination) {  }

  const char* get_msg_name() {return typeid(itti_enbue_deregister_request).name();};

};

//-----------------------------------------------------------------------------
class itti_enbue_packet : public itti_enbue_msg {
public:
  itti_enbue_packet(const task_id_t origin, const task_id_t destination):
    itti_enbue_msg(ENBUE_PACKET, origin, destination) {  }

  const char* get_msg_name() {return typeid(itti_enbue_packet).name();};
  int len;
  char pkt[1500];
  int siaddr;
  int giaddr;
};



#endif

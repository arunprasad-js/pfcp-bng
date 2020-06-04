/*
* Copyright (c) 2020 Ricardo Santos, BISDN GmbH
*
* Licensed under the License terms and conditions for use, reproduction,
* and distribution of OPENAIR 5G software (the “License”);
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*    https://www.openairinterface.org/?page_id=698
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
#ifndef FILE_BNGC_MSG_HANDLER_HPP_SEEN
#define FILE_BNGC_MSG_HANDLER_HPP_SEEN

#include "itti_msg_sxab.hpp" // Reusing itti sxab messages for internal communication
#include "rapidjson/document.h"

#define PPPD_EVENT "event"
#define PPPD_IP_ADDR "ip_addr"
#define PPPD_CTRL_IFNAME "ctrl_ifname"
#define PPPD_CALLED_SESSION_ID "called_station_id"
#define PPPD_CALLING_SESSION_ID "calling_station_id"
#define PPPD_PPPOE_SESSIONID "pppoe_sessionid"
#define PPPD_NAS_ID "nas_identifier"

#define SESSION_ACCT_START "session-acct-start"
#define SESSION_PRE_FINISHED "session-pre-finished"

#define DEFAULT_TRAFFIC_ENDPOINT_ID 1

namespace bngc {

bool validate_pppd_json_msg(rapidjson::Document &d);

seid_t generate_session_id(std::string nas_id, int pppoe_session_id);

int generate_upstream_pdr_ie(pfcp::create_pdr *create_pdr,
        std::string called_station_id, pfcp::far_id_t far_id);
int generate_downstream_pdr_ie(pfcp::create_pdr *create_pdr, std::string ip_addr,
        std::string calling_station_id, pfcp::far_id_t far_id);

int generate_upstream_far_ie(pfcp::create_far *create_far,
        pfcp::far_id_t *far_id);
int generate_downstream_far_ie(pfcp::create_far *create_far,
        pfcp::far_id_t *far_id, uint8_t endpoint_id);

bool get_vlan_tags_from_ctrl_ifname(std::string ctrl_ifname, pfcp::s_tag_t *s_tag,
        pfcp::c_tag_t *c_tag);

int generate_create_traffic_endpoint_ie(
        pfcp::create_traffic_endpoint *create_traffic_endpoint,
        uint8_t traffic_endpoint_id, std::string called_station_id,
        std::string ctrl_ifname, int pppoe_session_id_int);

int translate_ppp_to_pfcp_session_establishment(rapidjson::Document &d,
    itti_sxab_session_establishment_request *itti_sereq);

int translate_ppp_to_pfcp_session_deletion(rapidjson::Document &d,
    itti_sxab_session_deletion_request *itti_sdreq);

}

#endif /* FILE_BNGC_MSG_HANDLER_HPP_SEEN */

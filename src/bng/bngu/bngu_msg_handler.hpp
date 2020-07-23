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
#ifndef FILE_BNGU_MSG_HANDLER_HPP_SEEN
#define FILE_BNGU_MSG_HANDLER_HPP_SEEN

#include "msg_pfcp.hpp" // PFCP messages
#include <string>

namespace bngu {

bool process_session_establishment_request(
        pfcp::pfcp_session_establishment_request &request,
        pfcp::pfcp_session_establishment_response &response,
        const char *bngu_ip);

std::string get_upstream_dpdk_default_route(
        std::string upstream_route_ip_address,
        std::string bng_access_mac_address,
        std::string upstream_route_mac_address);

void get_upstream_dpdk_commands_from_pfcp(
        pfcp::pfcp_session_establishment_request &request,
        std::vector<std::string> *commands,
        std::string bng_access_mac_address);

void get_downstream_dpdk_commands_from_pfcp(
        pfcp::pfcp_session_establishment_request &request,
        std::vector<std::string> *commands, std::string bng_core_mac_address,
        std::string downstream_route_mac_address);

void get_upstream_dpdk_delete_commands(uint16_t s_tag, uint16_t c_tag,
        std::vector<std::string> *commands);

void get_downstream_dpdk_delete_commands(struct in_addr ipv4_address,
        std::vector<std::string> *commands);
}

#endif /* FILE_BNGU_MSG_HANDLER_HPP_SEEN */

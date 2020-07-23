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
#ifndef FILE_BNGU_CONFIG_HPP_SEEN
#define FILE_BNGU_CONFIG_HPP_SEEN

#include "rapidjson/document.h"

#define BNGC_IPV4_ADDRESS_OPTION "bngc_ip"
#define BNGU_IPV4_ADDRESS_OPTION "bngu_ip"
#define UPSTREAM_DPDK_HOST_OPTION "upstream_dpdk_host"
#define UPSTREAM_DPDK_PORT_OPTION "upstream_dpdk_port"
#define DOWNSTREAM_DPDK_HOST_OPTION "downstream_dpdk_host"
#define DOWNSTREAM_DPDK_PORT_OPTION "downstream_dpdk_port"
#define UPSTREAM_ROUTE_IP_ADDRESS_OPTION "upstream_route_ip_address"
#define UPSTREAM_ROUTE_MAC_ADDRESS_OPTION "upstream_route_mac_address"
#define BNG_ACCESS_MAC_ADDRESS_OPTION "bng_access_mac_address"
#define BNG_CORE_MAC_ADDRESS_OPTION "bng_core_mac_address"
#define DOWNSTREAM_ROUTE_MAC_ADDRESS_OPTION "downstream_route_mac_address"

#define DEFAULT_BNGU_CONFIG_FILE "bngu.json"

using namespace rapidjson;

namespace bngu {
    Document read_bngu_config_from_file(const char *config_file);
    Document read_bngu_config_from_file();
}

#endif /* FILE_BNGU_CONFIG_HPP_SEEN */

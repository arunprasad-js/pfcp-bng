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
#ifndef FILE_BNGC_CONFIG_HPP_SEEN
#define FILE_BNGC_CONFIG_HPP_SEEN

#include "rapidjson/document.h"

#define BNGC_IPV4_ADDRESS_OPTION "bngc_ip"
#define BNGU_IPV4_ADDRESS_OPTION "bngu_ip"
#define REDIS_SERVER_IP_OPTION "redis_server_ip"
#define REDIS_SERVER_PORT_OPTION "redis_server_port"
#define BNGU_ENDPOINTS_OPTION "bngu_endpoints"
#define NAS_ID_OPTION "nas_id"

#define DEFAULT_BNGC_CONFIG_FILE "bngc.json"

using namespace rapidjson;

namespace bngc {
    Document read_bngc_config_from_file(const char *config_file);
    Document read_bngc_config_from_file();
}

#endif /* FILE_BNGC_CONFIG_HPP_SEEN */

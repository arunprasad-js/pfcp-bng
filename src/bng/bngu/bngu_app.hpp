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
#ifndef FILE_BNGU_APP_HPP_SEEN
#define FILE_BNGU_APP_HPP_SEEN

#include "itti_msg_sxab.hpp"
#include <map>

namespace bngu {

typedef struct bngu_session_match_s {
    struct in_addr  ipv4_address;
    uint16_t c_tag;
    uint16_t s_tag;
    uint16_t pppoe_session_id;
} bngu_session_match_t;

class bngu_app {

private:
    void send_dpdk_cmd_request(task_id_t task_id, std::string command);

    void add_bngu_session(pfcp::pfcp_session_establishment_request &request);

public:
    explicit bngu_app();
    ~bngu_app();

    void handle_itti_sereq(std::shared_ptr<itti_sxab_session_establishment_request> msg);
    void handle_itti_sdreq(std::shared_ptr<itti_sxab_session_deletion_request> msg);

    std::map<seid_t, bngu_session_match_t> bngu_sessions;
};
}

#endif /* FILE_BNGU_APP_HPP_SEEN */

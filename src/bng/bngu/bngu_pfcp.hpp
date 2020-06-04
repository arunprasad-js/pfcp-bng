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
#ifndef FILE_BNGU_PFCP_HPP_SEEN
#define FILE_BNGU_PFCP_HPP_SEEN

#include "itti_msg_sxab.hpp" // Reusing itti sxab messages for internal communication
#include "bngu_pfcp_association.hpp"
#include "pfcp.hpp"

namespace bngu {

// Events for timer related tasks
#define TASK_BNGU_PFCP_TRIGGER_HEARTBEAT_REQUEST     (1)
#define TASK_BNGU_PFCP_TIMEOUT_HEARTBEAT_REQUEST     (2)

#define PFCP_HEARTBEAT_TIMEOUT 5 // pfcp.hpp sets this to ((1000) * (3 + 1 + 1))

class bngu_pfcp : public pfcp::pfcp_l4_stack {

private:
    void create_recovery_time_stamp();
    void prepare_up_function_features();
    void start_association(const std::string &bngu_ip, const std::string &bngc_ip);

    uint64_t recovery_time_stamp; //timestamp in seconds
    pfcp::up_function_features_s up_function_features;

public:
    //bngu_pfcp();
    bngu_pfcp(const std::string& bngu_ip_address, const unsigned short port_num,
            const std::string& bngc_ip_address, const util::thread_sched_params& sched_params);

    void send_pfcp_msg(itti_sxab_association_setup_request& request);
    void send_pfcp_msg(itti_sxab_session_establishment_response &response);
    void send_pfcp_msg(itti_sxab_session_deletion_response &response);

    void send_heartbeat_request(std::shared_ptr<pfcp_association>& a);
    void send_heartbeat_response(const endpoint& r_endpoint, const uint64_t trxn_id);

    void handle_receive_association_setup_response(pfcp::pfcp_msg& msg, const endpoint& r_endpoint);
    void handle_receive_heartbeat_request(pfcp::pfcp_msg& msg, const endpoint& r_endpoint);
    void handle_receive_heartbeat_response(pfcp::pfcp_msg& msg, const endpoint& r_endpoint);
    void handle_receive_session_establishment_request(pfcp::pfcp_msg& msg, const endpoint& r_endpoint);
    void handle_receive_session_modification_request(pfcp::pfcp_msg& msg, const endpoint& r_endpoint);
    void handle_receive_session_deletion_request(pfcp::pfcp_msg& msg, const endpoint& r_endpoint);

    void handle_receive_pfcp_msg(pfcp::pfcp_msg& msg, const endpoint& r_endpoint);
    void handle_receive(char* recv_buffer, const std::size_t bytes_transferred,
            const endpoint& r_endpoint);

    void time_out_itti_event(const uint32_t timer_id); // Used to handle event timeouts
};
}

#endif /* FILE_BNGU_PFCP_HPP_SEEN */

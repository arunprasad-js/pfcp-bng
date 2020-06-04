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
#ifndef FILE_BNGC_PFCP_HPP_SEEN
#define FILE_BNGC_PFCP_HPP_SEEN

#include "bngc_pfcp_association.hpp"
#include "itti_msg_sxab.hpp"
#include "pfcp.hpp"

namespace bngc {

// Events for timer related tasks
#define TASK_BNGC_PFCP_TRIGGER_HEARTBEAT_REQUEST     (1)
#define TASK_BNGC_PFCP_TIMEOUT_HEARTBEAT_REQUEST     (2)

#define PFCP_HEARTBEAT_TIMEOUT 5

class bngc_pfcp : public pfcp::pfcp_l4_stack {

private:
    void create_recovery_time_stamp();
    void prepare_cp_function_features();

    uint64_t recovery_time_stamp; //timestamp in seconds
    pfcp::cp_function_features_t cp_function_features;

    std::string bngc_ip;

public:
    //bngc_pfcp();
    bngc_pfcp(const std::string& ip_address, const unsigned short port_num,
            const util::thread_sched_params& sched_params);

    void send_heartbeat_request(std::shared_ptr<pfcp_association>& a);
    void send_heartbeat_response(const endpoint& r_endpoint,
            const uint64_t trxn_id);

    void send_pfcp_msg(itti_sxab_association_setup_response& asr);
    void send_pfcp_msg(itti_sxab_session_establishment_request& ser);
    void send_pfcp_msg(itti_sxab_session_deletion_request& sdr);

    void handle_receive_heartbeat_request(pfcp::pfcp_msg& msg,
            const endpoint& r_endpoint);
    void handle_receive_heartbeat_response(pfcp::pfcp_msg& msg,
            const endpoint& r_endpoint);
    void handle_receive_association_setup_request(pfcp::pfcp_msg& msg,
            const endpoint& r_endpoint);
    void handle_receive_session_establishment_response(pfcp::pfcp_msg& msg,
            const endpoint& r_endpoint);
    void handle_receive_session_deletion_response(pfcp::pfcp_msg& msg,
            const endpoint& r_endpoint);

    void handle_receive_pfcp_msg(pfcp::pfcp_msg& msg, const endpoint& r_endpoint);
    void handle_receive(char* recv_buffer, const std::size_t bytes_transferred,
            const endpoint& r_endpoint);

    void time_out_itti_event(const uint32_t timer_id); // Used to handle event timeouts
};
}
#endif /* FILE_BNGC_PFCP_HPP_SEEN */

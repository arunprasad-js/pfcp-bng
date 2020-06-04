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
#include "bngc_app.hpp"
#include "bngc_pfcp.hpp"
#include "itti.hpp" // Task id and related itti objects

#include <chrono>
#include <ctime>

using namespace bngc;
using namespace pfcp;

extern itti_mw *itti_inst;
extern bngc_app *bngc_app_inst;
extern bngc_pfcp *bngc_pfcp_inst;

void bngc_pfcp_task(void*);

void bngc_pfcp_task(void*)
{
    Logger::bngc_pfcp().debug("Starting BNGC PFCP thread loop with task ID %d", TASK_BNGC_PFCP);
    const task_id_t task_id = TASK_BNGC_PFCP;

    itti_inst->notify_task_ready(task_id);

    do {
        std::shared_ptr<itti_msg> shared_msg = itti_inst->receive_msg(task_id);
        auto *msg = shared_msg.get();
        switch (msg->msg_type)
        {
        // TODO: Switch cases for message types
        case SXAB_SESSION_ESTABLISHMENT_REQUEST:
            if (itti_sxab_session_establishment_request* ser =
                    dynamic_cast<itti_sxab_session_establishment_request*>(msg)) {
                bngc_pfcp_inst->send_pfcp_msg(std::ref(*ser));
            }

        case SXAB_SESSION_DELETION_REQUEST:
            if (itti_sxab_session_deletion_request* sdr =
                    dynamic_cast<itti_sxab_session_deletion_request*>(msg)) {
                bngc_pfcp_inst->send_pfcp_msg(std::ref(*sdr));
            }

        case TIME_OUT:
            if (itti_msg_timeout* to = dynamic_cast<itti_msg_timeout*>(msg)) {
                Logger::bngc_pfcp().debug("Received TIMEOUT msg. timer_id: %d, arg1_user: %d",
                        to->timer_id, to->arg1_user);
                switch (to->arg1_user) {
                case TASK_BNGC_PFCP_TRIGGER_HEARTBEAT_REQUEST:
                    pfcp_associations::get_instance().initiate_heartbeat_request(to->timer_id, to->arg2_user);
                    break;
                case TASK_BNGC_PFCP_TIMEOUT_HEARTBEAT_REQUEST:
                    pfcp_associations::get_instance().timeout_heartbeat_request(to->timer_id, to->arg2_user);
                    break;
                default:
                    bngc_pfcp_inst->time_out_itti_event(to->timer_id);
                }

            }

        case TERMINATE:
            if (itti_msg_terminate *terminate = dynamic_cast<itti_msg_terminate*>(msg)) {
                Logger::bngc_pfcp().info("Received terminate message");
                return;
            }
            break;
        default:
            Logger::bngc_pfcp().debug("Received msg with type %d", msg->msg_type);

        }

    } while(true);
}


bngc_pfcp::bngc_pfcp(const std::string& ip_address, const unsigned short port_num,
        const util::thread_sched_params& sched_params) : pfcp_l4_stack(ip_address,
        port_num, sched_params)
{
    Logger::bngc_pfcp().startup("Starting BNGC PFCP interface");

    create_recovery_time_stamp();
    prepare_cp_function_features();

    bngc_ip = ip_address;

    // Start task
    if (itti_inst->create_task(TASK_BNGC_PFCP, bngc_pfcp_task, nullptr)) {
        Logger::bngc_app().error( "Cannot create task TASK_BNGC_PFCP" );
        throw std::runtime_error( "Cannot create task TASK_BNGC_PFCP" );
    }
}

void bngc_pfcp::create_recovery_time_stamp()
{
    // See pgwc_sxab() in pgwc_sxab.cpp
    std::tm tm_epoch = {0};// Feb 8th, 2036
    tm_epoch.tm_year = 2036 - 1900; // years count from 1900
    tm_epoch.tm_mon = 2 - 1;    // months count from January=0
    tm_epoch.tm_mday = 8;         // days count from 1
    std::time_t time_epoch = std::mktime(&tm_epoch);
    std::chrono::time_point<std::chrono::system_clock> now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::time_t ellapsed = now_c - time_epoch;
    recovery_time_stamp = ellapsed;
}

void bngc_pfcp::prepare_cp_function_features()
{
    cp_function_features = {};
    cp_function_features.ovrl = 0;
    cp_function_features.load = 0;
}

void bngc_pfcp::handle_receive_pfcp_msg(pfcp_msg& msg, const endpoint& r_endpoint)
{
    switch(msg.get_message_type()) {

    case PFCP_ASSOCIATION_SETUP_REQUEST:
        handle_receive_association_setup_request(msg, r_endpoint);
        break;
    case PFCP_HEARTBEAT_REQUEST:
        handle_receive_heartbeat_request(msg, r_endpoint);
        break;
    case PFCP_HEARTBEAT_RESPONSE:
        handle_receive_heartbeat_response(msg, r_endpoint);
        break;
    case PFCP_SESSION_ESTABLISHMENT_RESPONSE:
        handle_receive_session_establishment_response(msg, r_endpoint);
        break;
    case PFCP_SESSION_DELETION_RESPONSE:
        handle_receive_session_deletion_response(msg, r_endpoint);
        break;
    default:
        Logger::bngc_pfcp().info("Received msg type %d", msg.get_message_type());
    }
}

void bngc_pfcp::handle_receive_heartbeat_request(pfcp::pfcp_msg& msg,
        const endpoint& r_endpoint)
{
    Logger::bngc_pfcp().debug("Parsing heartbeat request");
    bool error;
    uint64_t trxn_id;
    pfcp_heartbeat_request msg_ies_container = {};
    msg.to_core_type(msg_ies_container);

    handle_receive_message_cb(msg, r_endpoint, TASK_PGWC_SX, error, trxn_id);

    if(error) {
        Logger::bngc_pfcp().error("Error from handle_receive_message_cb");
        return;
    }

    if (not msg_ies_container.recovery_time_stamp.first) {
        Logger::bngc_pfcp().warn("Received SX HEARTBEAT REQUEST without recovery time stamp IE!, ignore message");
        return;
    }
    send_heartbeat_response(r_endpoint, trxn_id);
}

void bngc_pfcp::handle_receive_heartbeat_response(pfcp::pfcp_msg& msg,
        const endpoint& remote_endpoint)
{
    Logger::bngc_pfcp().debug("Parsing heartbeat response");
    bool error;
    uint64_t trxn_id;
    pfcp_heartbeat_response msg_ies_container = {};
    msg.to_core_type(msg_ies_container);

    handle_receive_message_cb(msg, remote_endpoint, TASK_PGWC_SX, error, trxn_id);

    if(error) {
        Logger::bngc_pfcp().error("Error from handle_receive_message_cb");
        return;
    }

    if (not msg_ies_container.recovery_time_stamp.first) {
      // Should be detected by lower layers
      Logger::bngc_pfcp().warn("Received SX HEARTBEAT REQUEST without recovery time stamp IE!, ignore message");
      return;
    }
    pfcp_associations::get_instance().handle_receive_heartbeat_response(trxn_id);
}

void bngc_pfcp::handle_receive_association_setup_request(pfcp::pfcp_msg& msg,
        const endpoint& r_endpoint)
{
    Logger::bngc_pfcp().info("Parsing association setup request");

    unsigned char bngc_in_addr_chr[sizeof (struct in_addr)+1]; // For bngc IP in binary format
    bool error;
    uint64_t trxn_id;

    // Convert BNGC IP string to binary format
    if (inet_pton (AF_INET, bngc_ip.c_str(), bngc_in_addr_chr) != 1) {
        Logger::bngc_pfcp().error("Invalid BNGC IPV4 address: %s", bngc_ip);
        return;
    }

    pfcp_association_setup_request msg_ies_container = {};
    msg.to_core_type(msg_ies_container);

    // Checking with PFCP if there are any previous procedures related with this message
    handle_receive_message_cb(msg, r_endpoint, TASK_BNGC_PFCP, error, trxn_id);

    if(error) {
        Logger::bngc_pfcp().error("Error from handle_receive_message_cb");
        return;
    }

    // Adding association
    pfcp_associations::get_instance().add_association(msg_ies_container.node_id.second,
            msg_ies_container.recovery_time_stamp.second);

    // Generating response
    itti_sxab_association_setup_response asr(TASK_BNGC_PFCP, TASK_BNGC_PFCP);
    asr.trxn_id = trxn_id;
    pfcp::cause_t cause = {.cause_value = pfcp::CAUSE_VALUE_REQUEST_ACCEPTED};
    asr.pfcp_ies.set(cause);

    pfcp::node_id_t node_id = {};

    // Populate node id with BNGC ip address
    pfcp::node_id_t bngc_node_id = {};
    bngc_node_id.node_id_type = pfcp::NODE_ID_TYPE_IPV4_ADDRESS;
    memcpy (&bngc_node_id.u1.ipv4_address, bngc_in_addr_chr, sizeof (struct in_addr));
    asr.pfcp_ies.set(bngc_node_id);

    // Recovery time stamp
    pfcp::recovery_time_stamp_t r = {.recovery_time_stamp = (uint32_t)recovery_time_stamp};
    asr.pfcp_ies.set(r);

    // CP features
    asr.pfcp_ies.set(cp_function_features);

    // Set remote endpoint as sender of request message
    asr.r_endpoint = r_endpoint;
    send_pfcp_msg(asr);
}

void bngc_pfcp::handle_receive_session_establishment_response(pfcp::pfcp_msg& msg,
        const endpoint& r_endpoint)
{
    bool error;
    uint64_t trxn_id;
    uint64_t seid;
    std::shared_ptr<itti_sxab_session_establishment_response> itti_seresp_ptr; // Shared pointer for SEResponse message

    // Converting PFCP message to SEResponse message
    pfcp_session_establishment_response pfcp_seresp = {};
    msg.to_core_type(pfcp_seresp);
    seid = msg.get_seid();

    // Checking with PFCP if there are any previous procedures related with this message
    handle_receive_message_cb(msg, r_endpoint, TASK_BNGC_PFCP, error, trxn_id);

    if(error) {
        Logger::bngc_pfcp().error("Error from handle_receive_message_cb");
        return;
    }

    // Creating new ITTI SEResponse message and sending it to BNGC_APP for processing
    itti_sxab_session_establishment_response *itti_seresp =
            new itti_sxab_session_establishment_response(TASK_BNGC_PFCP,
            TASK_BNGC_APP);
    itti_seresp->pfcp_ies = pfcp_seresp;
    itti_seresp->r_endpoint = r_endpoint;
    itti_seresp->trxn_id = trxn_id;
    itti_seresp->seid = seid;
    itti_seresp_ptr = std::shared_ptr<itti_sxab_session_establishment_response>(itti_seresp);

    int rc = itti_inst->send_msg(itti_seresp_ptr);
    if (rc != RETURNok) {
        Logger::bngc_pfcp().error("Failed sending ITTI message to TASK_BNGC_APP");
    }
}

void bngc_pfcp::handle_receive_session_deletion_response(pfcp::pfcp_msg& msg,
        const endpoint& r_endpoint)
{
    bool error;
    uint64_t trxn_id;
    uint64_t seid;
    std::shared_ptr<itti_sxab_session_deletion_response> itti_sdresp_ptr; // Shared pointer for SDResponse message

    // Converting PFCP message to SDResponse message
    pfcp_session_deletion_response pfcp_sdresp = {};
    msg.to_core_type(pfcp_sdresp);
    seid = msg.get_seid();

    // Checking with PFCP if there are any previous procedures related with this message
    handle_receive_message_cb(msg, r_endpoint, TASK_BNGC_PFCP, error, trxn_id);

    if(error) {
        Logger::bngc_pfcp().error("Error from handle_receive_message_cb");
        return;
    }

    // Creating new ITTI SDResponse message and sending it to BNGC_APP for processing
    itti_sxab_session_deletion_response *itti_sdresp =
            new itti_sxab_session_deletion_response(TASK_BNGC_PFCP,
            TASK_BNGC_APP);
    itti_sdresp->pfcp_ies = pfcp_sdresp;
    itti_sdresp->r_endpoint = r_endpoint;
    itti_sdresp->trxn_id = trxn_id;
    itti_sdresp->seid = seid;
    itti_sdresp_ptr = std::shared_ptr<itti_sxab_session_deletion_response>(itti_sdresp);

    int rc = itti_inst->send_msg(itti_sdresp_ptr);
    if (rc != RETURNok) {
        Logger::bngc_pfcp().error("Failed sending ITTI message to TASK_BNGC_APP");
    }
}

void bngc_pfcp::send_heartbeat_request(std::shared_ptr<pfcp_association>& a)
{
    pfcp::pfcp_heartbeat_request h = {};
    pfcp::recovery_time_stamp_t r = {.recovery_time_stamp = (uint32_t)recovery_time_stamp};
    h.set(r);

    pfcp::node_id_t& node_id = a->node_id;
    if (node_id.node_id_type == pfcp::NODE_ID_TYPE_IPV4_ADDRESS) {
        a->timer_heartbeat = itti_inst->timer_setup(PFCP_HEARTBEAT_TIMEOUT, 0,
                TASK_BNGC_PFCP, TASK_BNGC_PFCP_TIMEOUT_HEARTBEAT_REQUEST,
                a->hash_node_id);

        endpoint r_endpoint = endpoint(node_id.u1.ipv4_address, pfcp::default_port);
        a->trxn_id_heartbeat = generate_trxn_id();
        send_request(r_endpoint, h, TASK_BNGC_PFCP, a->trxn_id_heartbeat);
    }
}

void bngc_pfcp::send_heartbeat_response(const endpoint& r_endpoint,
        const uint64_t trxn_id)
{
    pfcp::pfcp_heartbeat_response h = {};
    pfcp::recovery_time_stamp_t r = {.recovery_time_stamp = (uint32_t)recovery_time_stamp};
    h.set(r);
    send_response(r_endpoint, h, trxn_id);
}

void bngc_pfcp::send_pfcp_msg(itti_sxab_association_setup_response& response) {
    send_response(response.r_endpoint, response.pfcp_ies, response.trxn_id);
}

void bngc_pfcp::send_pfcp_msg(itti_sxab_session_establishment_request& request)
{
    send_request(request.r_endpoint, request.seid, request.pfcp_ies,
            TASK_BNGC_PFCP, request.trxn_id);
}

void bngc_pfcp::send_pfcp_msg(itti_sxab_session_deletion_request& request)
{
    send_request(request.r_endpoint, request.seid, request.pfcp_ies,
            TASK_BNGC_PFCP, request.trxn_id);
}

void bngc_pfcp::handle_receive(char* recv_buffer,
        const std::size_t bytes_transferred,const endpoint& r_endpoint)
{
    Logger::bngc_pfcp().debug("handle_receive: Received %d bytes from %s",
            bytes_transferred, r_endpoint.toString().c_str());

    std::istringstream iss(std::istringstream::binary);
    iss.rdbuf()->pubsetbuf(recv_buffer,bytes_transferred);
    pfcp_msg msg = {};
    msg.remote_port = r_endpoint.port();

    try {
        msg.load_from(iss);
    } catch (pfcp_exception& e) {
        Logger::bngc_pfcp().error("Exception receiving message: %s", e.what());
        return;
    }

    handle_receive_pfcp_msg(msg, r_endpoint);
}

void bngc_pfcp::time_out_itti_event(const uint32_t timer_id)
{
  bool handled = false;
  time_out_event(timer_id, TASK_BNGC_PFCP, handled);
  if (!handled) {
    Logger::bngc_pfcp().error("Timer %d not Found", timer_id);
  }
}

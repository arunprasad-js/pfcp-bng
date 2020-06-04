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
#include "bngu_pfcp.hpp"
#include "itti.hpp" // Task id and related itti objects
#include "uint_generator.hpp" // Generating TXIDs

#include <chrono>
#include <ctime>

using namespace bngu;
using namespace pfcp;

extern itti_mw *itti_inst;
extern bngu_pfcp *bngu_pfcp_inst;

void bngu_pfcp_task(void *);

void bngu_pfcp_task(void *)
{
    Logger::bngu_pfcp().debug("Starting BNGU PFCP thread loop with task ID %d", TASK_BNGU_PFCP);
    const task_id_t task_id = TASK_BNGU_PFCP;

    itti_inst->notify_task_ready(task_id);

    do {
        std::shared_ptr<itti_msg> shared_msg = itti_inst->receive_msg(task_id);
        auto *msg = shared_msg.get();
        switch (msg->msg_type)
        {

        // TODO: Add remaining message types
        case SXAB_SESSION_ESTABLISHMENT_RESPONSE:
            if (itti_sxab_session_establishment_response* response =
                    dynamic_cast<itti_sxab_session_establishment_response*>(msg)) {
                bngu_pfcp_inst->send_pfcp_msg(std::ref(*response));
            }
            break;
        case SXAB_SESSION_DELETION_RESPONSE:
            if (itti_sxab_session_deletion_response* response =
                    dynamic_cast<itti_sxab_session_deletion_response*>(msg)) {
                bngu_pfcp_inst->send_pfcp_msg(std::ref(*response));
            }
            break;
        case TIME_OUT:
            if (itti_msg_timeout* to = dynamic_cast<itti_msg_timeout*>(msg)) {
                Logger::bngu_pfcp().debug("Received TIMEOUT msg. timer_id: %d, arg1_user: %d",
                        to->timer_id, to->arg1_user);
                switch (to->arg1_user) {
                case TASK_BNGU_PFCP_TRIGGER_HEARTBEAT_REQUEST:
                    pfcp_associations::get_instance().initiate_heartbeat_request(to->timer_id,
                            to->arg2_user);
                    break;
                case TASK_BNGU_PFCP_TIMEOUT_HEARTBEAT_REQUEST:
                    pfcp_associations::get_instance().timeout_heartbeat_request(to->timer_id,
                            to->arg2_user);
                    break;
                default:
                    bngu_pfcp_inst->time_out_itti_event(to->timer_id);
                }
            }
        case TERMINATE:
            if (itti_msg_terminate *terminate = dynamic_cast<itti_msg_terminate*>(msg)) {
                Logger::bngu_pfcp().info("Received terminate message");
                return;
            }
            break;
        default:
            Logger::bngu_pfcp().debug("Received msg with type %d", msg->msg_type);

        }

    } while(true);
}

bngu_pfcp::bngu_pfcp(const std::string& bngu_ip_address,
        const unsigned short port_num, const std::string& bngc_ip_address,
        const util::thread_sched_params& sched_params) : pfcp_l4_stack(bngu_ip_address,
        port_num, sched_params)
{
    Logger::bngu_pfcp().startup("Starting BNGU PFCP interface");

    create_recovery_time_stamp();
    prepare_up_function_features();

    // Start task
    if (itti_inst->create_task(TASK_BNGU_PFCP, bngu_pfcp_task, nullptr)) {
        Logger::bngu_app().error( "Cannot create task TASK_BNGU_PFCP" );
        throw std::runtime_error( "Cannot create task TASK_BNGU_PFCP" );
    }

    start_association(bngu_ip_address, bngc_ip_address);
}

void bngu_pfcp::create_recovery_time_stamp()
{
    // See spgwu_sx() in spgwu_sx.cpp
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

void bngu_pfcp::prepare_up_function_features()
{
    up_function_features = {};
    up_function_features.bucp = 0;
    up_function_features.ddnd = 0;
    up_function_features.dlbd = 0;
    up_function_features.trst = 0;
    up_function_features.ftup = 0;
    up_function_features.pfdm = 0;
    up_function_features.heeu = 0;
    up_function_features.treu = 0;
    up_function_features.empu = 0;
    up_function_features.pdiu = 0;
    up_function_features.udbc = 0;
    up_function_features.quoac = 0;
    up_function_features.trace = 0;
    up_function_features.frrt = 0;
    // TODO: Add BBF extended up function features with PPPOE
}

void bngu_pfcp::start_association(const std::string &bngu_ip, const std::string &bngc_ip)
{
    unsigned char bngc_in_addr_chr[sizeof (struct in_addr)+1]; // For bngc IP in binary format
    unsigned char bngu_in_addr_chr[sizeof (struct in_addr)+1]; // Same for bngu IP
    struct in_addr bngc_in_addr; // Used to populate r_endpoint with bngc IP

    Logger::bngu_pfcp().info("Starting association with BNGC IP %s", bngc_ip.c_str());

    // Convert BNGC IP string to binary format
    if (inet_pton (AF_INET, bngc_ip.c_str(), bngc_in_addr_chr) != 1) {
        Logger::bngu_pfcp().error("Invalid BNGC IPV4 address: %s", bngc_ip);
        return;
    }

    // Convert BNGU IP string to binary format
    if (inet_pton (AF_INET, bngu_ip.c_str(), bngu_in_addr_chr) != 1) {
        Logger::bngu_pfcp().error("Invalid BNGU IPV4 address: %s", bngu_ip);
        return;
    }

    pfcp::node_id_t bngc_node_id = {};
    bngc_node_id.node_id_type = pfcp::NODE_ID_TYPE_IPV4_ADDRESS;
    memcpy (&bngc_node_id.u1.ipv4_address, bngc_in_addr_chr, sizeof (struct in_addr));

    pfcp_associations::get_instance().create_pending_association(bngc_node_id);

    itti_sxab_association_setup_request asr(TASK_BNGU_PFCP, TASK_BNGU_PFCP);
    asr.trxn_id = util::uint_uid_generator<uint64_t>::get_instance().get_uid(); // Transaction ID

    // Populate node id with BNGU ip address
    pfcp::node_id_t bngu_node_id = {};
    bngu_node_id.node_id_type = pfcp::NODE_ID_TYPE_IPV4_ADDRESS;
    memcpy (&bngu_node_id.u1.ipv4_address, bngu_in_addr_chr, sizeof (struct in_addr));
    asr.pfcp_ies.set(bngu_node_id);

    // Recovery time stamp
    pfcp::recovery_time_stamp_t r = {.recovery_time_stamp = (uint32_t)recovery_time_stamp};
    asr.pfcp_ies.set(r);

    // UP features
    asr.pfcp_ies.set(up_function_features);
    // TODO: BBF UP features

    // Put bngc ip in in_addr struct
    memcpy (&bngc_in_addr, bngc_in_addr_chr, sizeof (struct in_addr));
    asr.r_endpoint = endpoint(bngc_in_addr, pfcp::default_port); // Set destination endpoint as bngc ip

    send_pfcp_msg(asr);
}

void bngu_pfcp::handle_receive_heartbeat_request(pfcp::pfcp_msg& msg,
        const endpoint& r_endpoint)
{
    bool error;
    uint64_t trxn_id;
    pfcp_heartbeat_request msg_ies_container = {};
    msg.to_core_type(msg_ies_container);

    handle_receive_message_cb(msg, r_endpoint, TASK_BNGU_PFCP, error, trxn_id);

    if(error) {
        Logger::bngu_pfcp().error("Error from handle_receive_message_cb");
        return;
    }

    if (not msg_ies_container.recovery_time_stamp.first) {
        // Should be detected by lower layers
        Logger::bngu_pfcp().warn("Received SX HEARTBEAT REQUEST without recovery time stamp IE!, ignore message");
        return;
    }
    Logger::bngu_pfcp().debug("Received SX HEARTBEAT REQUEST");
    send_heartbeat_response(r_endpoint, trxn_id);
}

void bngu_pfcp::handle_receive_heartbeat_response(pfcp::pfcp_msg& msg,
        const endpoint& r_endpoint)
{
    bool error;
    uint64_t trxn_id;
    pfcp_heartbeat_response msg_ies_container = {};
    msg.to_core_type(msg_ies_container);

    handle_receive_message_cb(msg, r_endpoint, TASK_BNGU_PFCP, error, trxn_id);

    if(error) {
        Logger::bngu_pfcp().error("Error from handle_receive_message_cb");
        return;
    }

    if (not msg_ies_container.recovery_time_stamp.first) {
        // Should be detected by lower layers
        Logger::bngu_pfcp().warn("Received SX HEARTBEAT RESPONSE without recovery time stamp IE!, ignore message");
        return;
    }
    Logger::bngu_pfcp().debug("Received SX HEARTBEAT RESPONSE");
    pfcp_associations::get_instance().handle_receive_heartbeat_response(trxn_id);
}

void bngu_pfcp::handle_receive_association_setup_response(pfcp_msg& msg,
        const endpoint& r_endpoint)
{
    Logger::bngu_pfcp().info("Processing association setup response");

    bool error;
    uint64_t trxn_id;

    // Converting PFCP message to association setup response message
    pfcp_association_setup_response pfcp_asresp = {};
    msg.to_core_type(pfcp_asresp);

    handle_receive_message_cb(msg, r_endpoint, TASK_BNGU_PFCP, error, trxn_id);

    if(error) {
        Logger::bngu_pfcp().error("Error from handle_receive_message_cb");
        return;
    }

    pfcp_associations::get_instance().add_association(pfcp_asresp.node_id.second,
            pfcp_asresp.recovery_time_stamp.second);
}

void bngu_pfcp::handle_receive_session_establishment_request(pfcp_msg& msg,
        const endpoint& r_endpoint)
{
    bool error;
    uint64_t trxn_id;
    uint64_t seid;
    std::shared_ptr<itti_sxab_session_establishment_request> itti_sereq_ptr; // Shared pointer for ser message

    // Converting PFCP message to SER message
    pfcp_session_establishment_request pfcp_sereq = {};
    msg.to_core_type(pfcp_sereq);
    seid = msg.get_seid();

    // Checking with PFCP if there are any previous procedures related with this message
    handle_receive_message_cb(msg, r_endpoint, TASK_BNGU_PFCP, error, trxn_id);

    if(error) {
        Logger::bngu_pfcp().error("Error from handle_receive_message_cb");
        return;
    }

    // Creating new ITTI SER message and sending it to BNGU_APP for processing
    itti_sxab_session_establishment_request *itti_sereq =
            new itti_sxab_session_establishment_request(TASK_BNGU_PFCP,
            TASK_BNGU_APP);
    itti_sereq->pfcp_ies = pfcp_sereq;
    itti_sereq->r_endpoint = r_endpoint;
    itti_sereq->trxn_id = trxn_id;
    itti_sereq->seid = seid;
    itti_sereq_ptr = std::shared_ptr<itti_sxab_session_establishment_request>(itti_sereq);

    int rc = itti_inst->send_msg(itti_sereq_ptr);
    if (rc != RETURNok) {
        Logger::bngu_pfcp().error("Failed sending ITTI message to TASK_BNGU_APP");
    }
}

void bngu_pfcp::handle_receive_session_modification_request(pfcp_msg& msg,
        const endpoint& r_endpoint)
{
    Logger::bngu_pfcp().debug("TODO: Parsing session modification request");
}

void bngu_pfcp::handle_receive_session_deletion_request(pfcp_msg& msg,
        const endpoint& r_endpoint)
{
    bool error;
    uint64_t trxn_id;
    uint64_t seid;
    std::shared_ptr<itti_sxab_session_deletion_request> itti_sdreq_ptr; // Shared pointer for sdr message

    // Converting PFCP message to SDR message
    pfcp_session_deletion_request pfcp_sdreq = {};
    msg.to_core_type(pfcp_sdreq);
    seid = msg.get_seid();

    // Checking with PFCP if there are any previous procedures related with this message
    handle_receive_message_cb(msg, r_endpoint, TASK_BNGU_PFCP, error, trxn_id);

    if(error) {
        Logger::bngu_pfcp().error("Error from handle_receive_message_cb");
        return;
    }

    // Creating new ITTI SER message and sending it to BNGU_APP for processing
    itti_sxab_session_deletion_request *itti_sdreq =
            new itti_sxab_session_deletion_request(TASK_BNGU_PFCP,
            TASK_BNGU_APP);
    itti_sdreq->pfcp_ies = pfcp_sdreq;
    itti_sdreq->r_endpoint = r_endpoint;
    itti_sdreq->trxn_id = trxn_id;
    itti_sdreq->seid = seid;
    itti_sdreq_ptr = std::shared_ptr<itti_sxab_session_deletion_request>(itti_sdreq);

    int rc = itti_inst->send_msg(itti_sdreq_ptr);
    if (rc != RETURNok) {
        Logger::bngu_pfcp().error("Failed sending ITTI message to TASK_BNGU_APP");
    }
}


void bngu_pfcp::handle_receive_pfcp_msg(pfcp_msg& msg, const endpoint& r_endpoint)
{
    switch(msg.get_message_type()) {

    case PFCP_ASSOCIATION_SETUP_RESPONSE:
        handle_receive_association_setup_response(msg, r_endpoint);
        break;

    case PFCP_HEARTBEAT_REQUEST:
        handle_receive_heartbeat_request(msg, r_endpoint);
        break;

    case PFCP_HEARTBEAT_RESPONSE:
        handle_receive_heartbeat_response(msg, r_endpoint);
        break;

    case PFCP_SESSION_ESTABLISHMENT_REQUEST:
        handle_receive_session_establishment_request(msg, r_endpoint);
        break;

    case PFCP_SESSION_MODIFICATION_REQUEST:
        handle_receive_session_modification_request(msg, r_endpoint);
        break;

    case PFCP_SESSION_DELETION_REQUEST:
        handle_receive_session_deletion_request(msg, r_endpoint);
        break;

    default:
        Logger::bngu_pfcp().debug("Received msg type %d", msg.get_message_type());
    }
}

void bngu_pfcp::send_pfcp_msg(itti_sxab_association_setup_request& request)
{
    send_request(request.r_endpoint, request.pfcp_ies, TASK_BNGU_PFCP, request.trxn_id);
}

void bngu_pfcp::send_pfcp_msg(itti_sxab_session_establishment_response &response)
{
    send_response(response.r_endpoint, response.seid, response.pfcp_ies, response.trxn_id);
}

void bngu_pfcp::send_pfcp_msg(itti_sxab_session_deletion_response &response)
{
    send_response(response.r_endpoint, response.seid, response.pfcp_ies, response.trxn_id);
}

void bngu_pfcp::send_heartbeat_request(std::shared_ptr<pfcp_association>& a)
{
    pfcp::pfcp_heartbeat_request h = {};
    pfcp::recovery_time_stamp_t r = {.recovery_time_stamp = (uint32_t)recovery_time_stamp};
    h.set(r);

    pfcp::node_id_t& node_id = a->node_id;
    if (node_id.node_id_type == pfcp::NODE_ID_TYPE_IPV4_ADDRESS) {
        a->timer_heartbeat = itti_inst->timer_setup(PFCP_HEARTBEAT_TIMEOUT, 0,
                TASK_BNGU_PFCP, TASK_BNGU_PFCP_TIMEOUT_HEARTBEAT_REQUEST,
                a->hash_node_id);

        endpoint r_endpoint = endpoint(node_id.u1.ipv4_address, pfcp::default_port);
        a->trxn_id_heartbeat = generate_trxn_id();
        send_request(r_endpoint, h, TASK_BNGU_PFCP, a->trxn_id_heartbeat);
    }
}

void bngu_pfcp::send_heartbeat_response(const endpoint& r_endpoint,
        const uint64_t trxn_id)
{
    pfcp::pfcp_heartbeat_response h = {};
    pfcp::recovery_time_stamp_t r = {.recovery_time_stamp = (uint32_t)recovery_time_stamp};
    h.set(r);
    send_response(r_endpoint, h, trxn_id);
}

void bngu_pfcp::handle_receive(char* recv_buffer,
        const std::size_t bytes_transferred,const endpoint& r_endpoint)
{
    Logger::bngu_pfcp().debug("handle_receive: Received %d bytes from %s",
            bytes_transferred, r_endpoint.toString().c_str());

    std::istringstream iss(std::istringstream::binary);
    iss.rdbuf()->pubsetbuf(recv_buffer,bytes_transferred);
    pfcp_msg msg = {};
    msg.remote_port = r_endpoint.port();

    try {
        msg.load_from(iss);
    } catch (pfcp_exception& e) {
        Logger::bngu_pfcp().error("Exception receiving message: %s", e.what());
        return;
    }

    handle_receive_pfcp_msg(msg, r_endpoint);
}

void bngu_pfcp::time_out_itti_event(const uint32_t timer_id)
{
  bool handled = false;
  time_out_event(timer_id, TASK_BNGU_PFCP, handled);
  if (!handled) {
    Logger::bngu_pfcp().error("Timer %d not Found", timer_id);
  }
}

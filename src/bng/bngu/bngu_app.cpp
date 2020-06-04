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
#include "bngu_app.hpp"
#include "bngu_config.hpp"
#include "bngu_dpdk_connector.hpp"
#include "bngu_msg_handler.hpp"
#include "bngu_pfcp.hpp"
#include "itti.hpp"
#include "logger.hpp"
#include "thread_sched.hpp"

#include <unistd.h>
#include <utility>

#define BNGU_SCHED_PRIORITY 84
#define BNGU_PFCP_SCHED_PRIORITY 84

using namespace bngu;

extern bngu_app *bngu_app_inst;
bngu_pfcp *bngu_pfcp_inst = nullptr;
DPDKTelnetCLI *bngu_dpdk_upstream_inst = nullptr;
DPDKTelnetCLI *bngu_dpdk_downstream_inst = nullptr;
extern itti_mw *itti_inst;
extern Document bngu_config;

util::thread_sched_params bngu_sched_params; // BNGU App thread parameters
util::thread_sched_params bngu_pfcp_sched_params; // BNGU PFCP thread parameters

void bngu_app_task (void*); // Message loop task

void bngu_app_task (void*)
{
    Logger::bngu_app().debug("Starting BNGU thread loop with task ID %d", TASK_BNGU_APP);
    const task_id_t task_id = TASK_BNGU_APP;

    bngu_sched_params.sched_priority = BNGU_SCHED_PRIORITY;
    bngu_sched_params.apply(task_id, Logger::bngu_app());

    itti_inst->notify_task_ready(task_id);

    do {
        std::shared_ptr<itti_msg> shared_msg = itti_inst->receive_msg(task_id);
        auto *msg = shared_msg.get();
        switch (msg->msg_type)
        {
        // TODO: Switch cases for message types
        case SXAB_SESSION_ESTABLISHMENT_REQUEST:
            bngu_app_inst->handle_itti_sereq(std::static_pointer_cast<itti_sxab_session_establishment_request>(shared_msg));
            break;

        case SXAB_SESSION_DELETION_REQUEST:
            bngu_app_inst->handle_itti_sdreq(std::static_pointer_cast<itti_sxab_session_deletion_request>(shared_msg));
            break;

        case TERMINATE:
            if (itti_msg_terminate *terminate = dynamic_cast<itti_msg_terminate*>(msg)) {
                Logger::bngu_app().info("Received terminate message");

                Logger::bngu_app().debug("Triggering close on BNGU DPDK connectors");
                if (bngu_dpdk_upstream_inst) {
                    bngu_dpdk_upstream_inst->close();
                }
                if (bngu_dpdk_downstream_inst) {
                    bngu_dpdk_downstream_inst->close();
                }
                return;
            }
            break;
        default:
            Logger::bngu_app().debug("Received msg with type %d", msg->msg_type);

        }
    } while(true);

}

bngu_app::bngu_app() : bngu_sessions()
{
    Logger::bngu_app().startup("Starting BNG user plane app");

    if (itti_inst->create_task(TASK_BNGU_APP, bngu_app_task, nullptr)) {
        Logger::bngu_app().error( "Cannot create task TASK_BNGU_APP" );
        throw std::runtime_error( "Cannot create task TASK_BNGU_APP" );
    }

    std::string bngu_ip = bngu_config[BNGU_IPV4_ADDRESS_OPTION].GetString();
    std::string bngc_ip = bngu_config[BNGC_IPV4_ADDRESS_OPTION].GetString();

    std::string dpdk_up_ip = bngu_config[UPSTREAM_DPDK_HOST_OPTION].GetString();
    int dpdk_up_port = bngu_config[UPSTREAM_DPDK_PORT_OPTION].GetInt();

    std::string dpdk_down_ip = bngu_config[DOWNSTREAM_DPDK_HOST_OPTION].GetString();
    int dpdk_down_port = bngu_config[DOWNSTREAM_DPDK_PORT_OPTION].GetInt();

    std::string gateway_ip_address = bngu_config[GATEWAY_IP_ADDRESS_OPTION].GetString();
    std::string gateway_mac_address = bngu_config[GATEWAY_MAC_ADDRESS_OPTION].GetString();
    std::string downstream_mac_address = bngu_config[DOWNSTREAM_MAC_ADDRESS_OPTION].GetString();

    Logger::bngu_app().debug("Instantiating interfaces");
    bngu_pfcp_sched_params.sched_priority = BNGU_PFCP_SCHED_PRIORITY;
    Logger::bngu_app().debug("Creating BNGU_PFCP interface bound to %s:%d",
            bngu_ip.c_str(), pfcp::default_port);
    bngu_pfcp_inst = new bngu_pfcp(bngu_ip, pfcp::default_port, bngc_ip,
            bngu_pfcp_sched_params);

    Logger::bngu_app().debug("Instantiating DPDK telnet connectors");
    bngu_dpdk_upstream_inst = new DPDKTelnetCLI(dpdk_up_ip.c_str(),
            dpdk_up_port, true);
    bngu_dpdk_downstream_inst = new DPDKTelnetCLI(dpdk_down_ip.c_str(),
            dpdk_down_port, false);

    bngu_dpdk_upstream_inst->connect_telnet_client();
    bngu_dpdk_downstream_inst->connect_telnet_client();

    bngu_dpdk_upstream_inst->install_default_upstream_route(gateway_ip_address,
            gateway_mac_address, downstream_mac_address);

    Logger::bngu_app().startup("Nailed startup");
}

bngu_app::~bngu_app()
{
    Logger::bngu_app().debug("Deleting BNGU_PFCP interfaces");
    if (bngu_pfcp_inst) {
        delete bngu_pfcp_inst;
    }

    Logger::bngu_app().debug("Deleting DPDK telnet connectors");
    if (bngu_dpdk_upstream_inst) {
        delete bngu_dpdk_upstream_inst;
    }
    if (bngu_dpdk_downstream_inst) {
        delete bngu_dpdk_downstream_inst;
    }
}

void bngu_app::handle_itti_sereq(
        std::shared_ptr<itti_sxab_session_establishment_request> msg)
{
    Logger::bngu_app().info("Received SERequest. SEID: " SEID_FMT " ", msg->seid);

    Logger::bngu_app().debug("Local endpoint: %s . Remote endpoint: %s",
            msg->l_endpoint.toString().c_str(), msg->r_endpoint.toString().c_str());

    // Shared pointers between tasks
    std::shared_ptr<itti_sxab_session_establishment_response> shared_sxab_msg;

    int rc; // Return code from itti send msg call
    bool send_to_dpdk; // Set to true if IEs in request are valid

    // Creating session establishment response ITTI message
    itti_sxab_session_establishment_response *sereq_resp =
            new itti_sxab_session_establishment_response(TASK_BNGU_APP, TASK_BNGU_PFCP);

    // Process request and verify correctness of request IEs
    std::string bngu_ip = bngu_config[BNGU_IPV4_ADDRESS_OPTION].GetString();
    send_to_dpdk = process_session_establishment_request(msg->pfcp_ies,
            sereq_resp->pfcp_ies, bngu_ip.c_str());

    // Populate ITTI response message fields
    sereq_resp->trxn_id = msg->trxn_id; // Same transaction ID
    //sereq_resp->seid = msg->pfcp_ies.cp_fseid.second.seid; // Set SEID to CP FSEID from request message
    sereq_resp->seid = msg->seid; // Same SEID
    sereq_resp->r_endpoint = msg->r_endpoint; // Same remote endpoint
    sereq_resp->l_endpoint = msg->l_endpoint; // Same local endpoint

    // Creating shared pointer from message
    shared_sxab_msg = std::shared_ptr<itti_sxab_session_establishment_response>(sereq_resp);

    // Sending message to BNGU_PFCP interface task
    rc = itti_inst->send_msg(shared_sxab_msg);
    if (rc != RETURNok) {
        Logger::bngu_app().error("Error sending SEResponse message to TASK_BNGU_PFCP");
        return;
    }

    // If PFCP request message was not valid, do not send message to DPDK
    if (!send_to_dpdk) {
        Logger::bngu_app().debug("Invalid session request. Not sending anything to DPDK");
        return;
    }

    std::vector<std::string> *uplink_commands = new std::vector<std::string>();
    std::vector<std::string> *downlink_commands = new std::vector<std::string>();

    std::string gateway_address = bngu_config[GATEWAY_MAC_ADDRESS_OPTION].GetString();

    // Process upstream dpdk commands
    get_upstream_dpdk_commands_from_pfcp(msg->pfcp_ies, uplink_commands,
            gateway_address);

    for(int i=0; i < uplink_commands->size(); i++) {
        Logger::bngu_app().debug("Creating request for uplink command: %s",
            uplink_commands->at(i).c_str());
        send_dpdk_cmd_request(TASK_DPDK_UPSTREAM, uplink_commands->at(i));
    }

    // Process downstream dpdk commands
    get_downstream_dpdk_commands_from_pfcp(msg->pfcp_ies, downlink_commands);

    for(int i=0; i < downlink_commands->size(); i++) {
        Logger::bngu_app().debug("Creating request for downlink command: %s",
            downlink_commands->at(i).c_str());
        send_dpdk_cmd_request(TASK_DPDK_DOWNSTREAM, downlink_commands->at(i));
    }

    delete uplink_commands;
    delete downlink_commands;

    // Locally map session for generating DPDK commands when deleting
    add_bngu_session(msg->pfcp_ies);
}

void bngu_app::handle_itti_sdreq(std::shared_ptr<itti_sxab_session_deletion_request> msg)
{
    Logger::bngu_app().info("Received SDRequest. SEID: " SEID_FMT " ", msg->seid);

    Logger::bngu_app().debug("Local endpoint: %s . Remote endpoint: %s",
            msg->l_endpoint.toString().c_str(), msg->r_endpoint.toString().c_str());

    // Shared pointers between tasks
    std::shared_ptr<itti_sxab_session_deletion_response> shared_sxab_msg;

    int rc; // Return code from itti send msg call
    bool send_to_dpdk; // Set to true if IEs in request are valid

    // Creating session deletion response ITTI message
    itti_sxab_session_deletion_response *sdreq_resp =
            new itti_sxab_session_deletion_response(TASK_BNGU_APP, TASK_BNGU_PFCP);

    // Populate ITTI response message fields
    sdreq_resp->trxn_id = msg->trxn_id; // Same transaction ID
    sdreq_resp->seid = msg->seid; // Same SEID
    sdreq_resp->r_endpoint = msg->r_endpoint; // Same remote endpoint
    sdreq_resp->l_endpoint = msg->l_endpoint; // Same local endpoint

    pfcp::cause_t cause_ie = {}; // Cause of the response (accepted or not found)

    bngu_session_match_t session_match = {};

    auto itr = bngu_sessions.find(msg->seid); // Look up session id
    if (itr != bngu_sessions.end()) {
        seid_t seid = itr->first;

        Logger::bngu_app().info("Found session id " SEID_FMT "", seid);
        session_match = itr->second;

        std::vector<std::string> *uplink_commands = new std::vector<std::string>();
        std::vector<std::string> *downlink_commands = new std::vector<std::string>();

        get_upstream_dpdk_delete_commands(session_match.s_tag,
                session_match.c_tag, uplink_commands);

        for(int i=0; i < uplink_commands->size(); i++) {
            Logger::bngu_app().debug("Creating request for uplink command: %s",
                uplink_commands->at(i).c_str());
            send_dpdk_cmd_request(TASK_DPDK_UPSTREAM, uplink_commands->at(i));
        }

        // Process downstream dpdk commands
        get_downstream_dpdk_delete_commands(session_match.ipv4_address, downlink_commands);

        for(int i=0; i < downlink_commands->size(); i++) {
            Logger::bngu_app().debug("Creating request for downlink command: %s",
                downlink_commands->at(i).c_str());
            send_dpdk_cmd_request(TASK_DPDK_DOWNSTREAM, downlink_commands->at(i));
        }

        bngu_sessions.erase(seid);
        cause_ie.cause_value = pfcp::CAUSE_VALUE_REQUEST_ACCEPTED;
    } else {
        Logger::bngu_app().warn("Could not find session id " SEID_FMT "", msg->seid);
        cause_ie.cause_value = pfcp::CAUSE_VALUE_SESSION_CONTEXT_NOT_FOUND;
    }

    sdreq_resp->pfcp_ies.set(cause_ie);

    // Creating shared pointer from message
    shared_sxab_msg = std::shared_ptr<itti_sxab_session_deletion_response>(sdreq_resp);

    // Sending message to BNGU_PFCP interface task
    rc = itti_inst->send_msg(shared_sxab_msg);
    if (rc != RETURNok) {
        Logger::bngu_app().error("Error sending SDResponse message to TASK_BNGU_PFCP");
        return;
    }
}

void bngu_app::send_dpdk_cmd_request(task_id_t task_id, std::string command)
{
    int rc; // Return code from itti send msg call
    std::shared_ptr<itti_dpdk_send_msg_request> shared_dpdk_msg;

    // Creating DPDK message request ITTI message with command obtained from PFCP msg
    itti_dpdk_send_msg_request *dpdk_msg_req = new itti_dpdk_send_msg_request(
            TASK_BNGU_APP, task_id, command);

    // Creating shared pointer from message
    shared_dpdk_msg = std::shared_ptr<itti_dpdk_send_msg_request>(dpdk_msg_req);

    // Sending message to DPDK interface task
    rc = itti_inst->send_msg(shared_dpdk_msg);
    if (rc != RETURNok) {
        Logger::bngu_app().error("Error sending dpdk send message request to %d",
                task_id);
        return;
    }
}

void bngu_app::add_bngu_session(pfcp::pfcp_session_establishment_request &request)
{
    bngu_session_match_t session_match = {};
    seid_t seid = request.cp_fseid.second.seid;

    pfcp::create_traffic_endpoint cte;

    // Read values from request PDRs
    for (auto it : request.create_pdrs) {
        pfcp::create_pdr& pdr = it;
        pfcp::pdi pdi = pdr.pdi.second;

        // Destination IP from UE IP Address
        if (pdi.ue_ip_address.first) {
            memcpy (&session_match.ipv4_address, &pdi.ue_ip_address.second.ipv4_address, sizeof (struct in_addr));
        }
    }

    // Read values from Create Traffic Endpoint IE
    if (request.create_traffic_endpoint.first) {
        cte = request.create_traffic_endpoint.second;
        if(cte.s_tag.first) {
            session_match.s_tag = cte.s_tag.second.svid_value;
        }
        if(cte.c_tag.first) {
            session_match.c_tag = cte.c_tag.second.cvid_value;
        }
        if(cte.pppoe_session_id.first) {
            session_match.pppoe_session_id = cte.pppoe_session_id.second.pppoe_session_id;
        }
    }

    bngu_sessions.insert(std::make_pair(seid, session_match));
}

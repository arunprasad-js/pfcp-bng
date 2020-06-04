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
#include "bngc_config.hpp"
#include "bngc_pfcp.hpp"
#include "itti.hpp"
#include "logger.hpp"
#include "thread_sched.hpp"

#include "bngc_msg_handler.hpp"

#define BNGC_SCHED_PRIORITY 84
#define BNGC_PFCP_SCHED_PRIORITY 84

using namespace bngc;
using namespace rapidjson;

extern bngc_app *bngc_app_inst;
bngc_pfcp *bngc_pfcp_inst = nullptr;
extern itti_mw *itti_inst;
extern Document bngc_config;

util::thread_sched_params bngc_sched_params; // BNGC App thread parameters
util::thread_sched_params bngc_pfcp_sched_params; // BNGC PFCP thread parameters

void bngc_app_task(void*); // Message loop task

void bngc_app_task(void*)
{
    Logger::bngc_app().debug("Starting BNGC thread loop with task ID %d", TASK_BNGC_APP);
    const task_id_t task_id = TASK_BNGC_APP;

    bngc_sched_params.sched_priority = BNGC_SCHED_PRIORITY;
    bngc_sched_params.apply(task_id, Logger::bngc_app());

    itti_inst->notify_task_ready(task_id);

    do {
        std::shared_ptr<itti_msg> shared_msg = itti_inst->receive_msg(task_id);
        auto *msg = shared_msg.get();
        switch (msg->msg_type)
        {
        // TODO: Switch cases for message types
        case SXAB_SESSION_ESTABLISHMENT_RESPONSE:
            if (itti_sxab_session_establishment_response* response =
                    dynamic_cast<itti_sxab_session_establishment_response*>(msg)) {
                bngc_app_inst->handle_session_establishment_response(std::ref(*response));
            }
            break;

        case SXAB_SESSION_DELETION_RESPONSE:
            if (itti_sxab_session_deletion_response* response =
                    dynamic_cast<itti_sxab_session_deletion_response*>(msg)) {
                bngc_app_inst->handle_session_deletion_response(std::ref(*response));
            }
            break;

        case TERMINATE:
            if (itti_msg_terminate *terminate = dynamic_cast<itti_msg_terminate*>(msg)) {
                Logger::bngc_app().info("Received terminate message");
                return;
            }
            break;
        default:
            Logger::bngc_app().debug("Received msg with type %d", msg->msg_type);

        }
    } while(true);

}

bngc_app::bngc_app() : bngu_endpoints()
{
    Logger::bngc_app().startup("Starting BNG control plane app");

    if (itti_inst->create_task(TASK_BNGC_APP, bngc_app_task, nullptr)) {
        Logger::bngc_app().error( "Cannot create task TASK_BNGC_APP" );
        throw std::runtime_error( "Cannot create task TASK_BNGC_APP" );
    }

    std::string bngc_ip = bngc_config[BNGC_IPV4_ADDRESS_OPTION].GetString();

    process_bngu_endpoints();

    bngc_pfcp_sched_params.sched_priority = BNGC_PFCP_SCHED_PRIORITY;

    bngc_pfcp_inst = new bngc_pfcp(bngc_ip, pfcp::default_port,
            bngc_pfcp_sched_params);

    Logger::bngc_app().startup("Nailed startup");
}

bngc_app::~bngc_app()
{
    Logger::bngc_app().debug("Deleting BNGC_PFCP interface");
    if (bngc_pfcp_inst) {
        delete bngc_pfcp_inst;
    }
}

void bngc_app::process_bngu_endpoints()
{
    const Value& endpoints = bngc_config[BNGU_ENDPOINTS_OPTION];
    unsigned char in_addr_chr[sizeof (struct in_addr)+1]; // For translating ip addr to binary format

    assert(endpoints.IsArray());
    for (SizeType i = 0; i < endpoints.Size(); i++) {
        auto bngu_endpoint_obj = endpoints[i].GetObject();
        std::string bngu_ip_str = bngu_endpoint_obj[BNGU_IPV4_ADDRESS_OPTION].GetString();

        struct in_addr bngu_ip;

        // Convert UEIP string to binary format
        if (inet_pton (AF_INET, bngu_ip_str.c_str(), in_addr_chr) != 1) {
            Logger::bngc_app().error("Invalid BNGU IPV4 address: %s", bngu_ip_str.c_str());
            return;
        }

        memcpy (&bngu_ip, in_addr_chr, sizeof (struct in_addr));
        endpoint bngu_endpoint(bngu_ip, pfcp::default_port);

        // If it has a NAS ID we add it to the map
        if(bngu_endpoint_obj.HasMember(NAS_ID_OPTION)) {
            std::string nas_id = bngu_endpoint_obj[NAS_ID_OPTION].GetString();
            bngu_endpoints.insert(std::make_pair(nas_id, bngu_endpoint));
            Logger::bngc_app().debug("New endpoint. NAS ID: %s, endpoint: %s",
                    nas_id.c_str(), bngu_endpoint.toString().c_str());
        }
        // Otherwise we assume there is only one BNGU and assign it the default NAS ID
        else {
            bngu_endpoints.insert(std::make_pair(std::string(DEFAULT_NAS_ID), bngu_endpoint));
            Logger::bngc_app().debug("New endpoint with default NAS ID: %s, endpoint: %s",
                    DEFAULT_NAS_ID, bngu_endpoint.toString());
            return;
        }
    }
}

void bngc_app::handle_session_establishment_response(itti_sxab_session_establishment_response& response)
{
    Logger::bngc_app().debug("Processing session establishment response message. Not doing anything at the moment");
}

void bngc_app::handle_session_deletion_response(itti_sxab_session_deletion_response& response)
{
    Logger::bngc_app().debug("Processing session deletion response message. Not doing anything at the moment");
}

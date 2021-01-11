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
#include "bngc_msg_handler.hpp"
#include "itti_msg_sxab.hpp"
#include "bngc_enbue_msg_handler.hpp"
#include "itti_msg_enbue.hpp"
#include "itti.hpp" // Task id and related itti objects
#include "redis_client.hpp"

#include <sw/redis++/redis++.h>
#include "rapidjson/document.h"     // rapidjson's DOM-style API
#include "rapidjson/prettywriter.h" // for stringify JSON

#include <chrono>
#include <iostream>

#define REDIS_CHANNEL "accel-ppp"
#define REDIS_PUB_CHANNEL "accel-ppp-5g"
#define REDIS_SOCKET_TIMEOUT 500

using namespace sw::redis;
using namespace bngc;
using namespace rapidjson;
using namespace bngc_enbue;

extern itti_mw *itti_inst;
extern redis_client *redis_client_inst;
Redis *redis = nullptr;

// ITTI thread task
void redis_itti_task(void *);

void redis_itti_task(void *)
{
    Logger::redis_client().debug("Starting redis ITTI thread loop with task ID %d",
            TASK_REDIS_CLIENT);
    const task_id_t task_id = TASK_REDIS_CLIENT;

    itti_inst->notify_task_ready(task_id);

    do {
        std::shared_ptr<itti_msg> shared_msg = itti_inst->receive_msg(task_id);
        auto *msg = shared_msg.get();
        switch (msg->msg_type)
        {
        case NEW_REDIS_MSG:
            if (itti_new_redis_msg* new_redis_msg =
                    dynamic_cast<itti_new_redis_msg*>(msg)) {
                // TODO: Put this in && condition
                if (redis_client_inst != nullptr) {
                    redis_client_inst->process_redis_msg(std::ref(*new_redis_msg));
                }
            }
            break;
	case NEW_REDIS_PUB_MSG:
            if (itti_new_redis_pub_msg* new_redis_pub_msg =
                    dynamic_cast<itti_new_redis_pub_msg*>(msg)) {
                // TODO: Put this in && condition
                if (redis_client_inst != nullptr) {
                    redis_client_inst->publish_redis_msg(std::ref(*new_redis_pub_msg));
                }
            }
	    break;
        case TERMINATE:
            if (itti_msg_terminate *terminate = dynamic_cast<itti_msg_terminate*>(msg)) {
                Logger::redis_client().info("Received terminate message");
                return;
            }
            break;
        default:
            Logger::redis_client().debug("Received msg with type %d", msg->msg_type);

        }
    } while(true);
}

void msg_callback(std::string channel, std::string msg)
{
    Logger::redis_client().debug("Consumed message: %s : %s", channel.c_str(),
            msg.c_str());

    int rc; // Return code for requests

    // Shared pointer for itti redis message
    std::shared_ptr<itti_new_redis_msg> itti_redis_msg_ptr;

    // Creating ITTI msg. We set the source task as BNGC APP since this thread is not an itti task
    itti_new_redis_msg *redis_msg = new itti_new_redis_msg(TASK_BNGC_APP, TASK_REDIS_CLIENT, msg);
    // redis_msg->redis_msg = msg;

    itti_redis_msg_ptr = std::shared_ptr<itti_new_redis_msg>(redis_msg);

    rc = itti_inst->send_msg(itti_redis_msg_ptr);
    if (rc != RETURNok) {
        Logger::redis_client().error("Error sending redis ITTI msg to redis tak");
    }
}

/* Hash Table creation */
/* Key - IMSI 
 * Fields 
 * - pppoe_id
 * - ip_addr
 * - circuit_id
 * - remote_id */

void construct_message (std::string ip_addr, int session_id, std::string ifname)
{
    std::string msg;
    int rc; // Return code for requests
    rapidjson::Document d;

    d.SetObject();

    rapidjson::Document::AllocatorType& allocator = d.GetAllocator();

    rapidjson::Value value(ip_addr.c_str(), ip_addr.size(), d.GetAllocator());
    rapidjson::Value ifname_value(ifname.c_str(), ifname.size(), d.GetAllocator());

    d.AddMember("ip_addr", value, allocator);
    d.AddMember("pppoe_id", session_id, allocator);
    d.AddMember("ctrl_ifname", ifname_value, allocator);

    rapidjson::StringBuffer strbuf;
    rapidjson::Writer<rapidjson::StringBuffer> writer(strbuf);
    d.Accept(writer);

    msg = strbuf.GetString();

    Logger::redis_client().debug("Sending Message to redis: %s ", strbuf.GetString());

    // Shared pointer for itti redis message
    std::shared_ptr<itti_new_redis_pub_msg> itti_redis_pub_msg_ptr;

    // Creating ITTI msg. We set the source task as BNGC APP since this thread is not an itti task
    itti_new_redis_pub_msg *redis_msg = new itti_new_redis_pub_msg(TASK_BNGC_APP, TASK_REDIS_CLIENT, msg);

    itti_redis_pub_msg_ptr = std::shared_ptr<itti_new_redis_pub_msg>(redis_msg);

    rc = itti_inst->send_msg(itti_redis_pub_msg_ptr);
    if (rc != RETURNok) {
	Logger::redis_client().error("Error sending redis ITTI msg to redis tak");
    }
    return;
}

void publish_msg (std::string channel, std::string msg)
{
    int rc; // Return code for requests

    Logger::redis_client().debug("PUBLISH message on channel %s Message: %s", channel.c_str(),
            msg.c_str());

    // Shared pointer for itti redis message
    std::shared_ptr<itti_new_redis_pub_msg> itti_redis_pub_msg_ptr;

    // Creating ITTI msg. We set the source task as BNGC APP since this thread is not an itti task
    itti_new_redis_pub_msg *redis_msg = new itti_new_redis_pub_msg(TASK_BNGC_APP, TASK_REDIS_CLIENT, msg);

    itti_redis_pub_msg_ptr = std::shared_ptr<itti_new_redis_pub_msg>(redis_msg);

    rc = itti_inst->send_msg(itti_redis_pub_msg_ptr);
    if (rc != RETURNok) {
        Logger::redis_client().error("Error sending redis ITTI msg to redis tak");
    }
}

// Used for polling redis messages in separate thread
void redis_client_task(std::string server_ip, int server_port, std::string channel)
{

    Logger::redis_client().info("Redis client thread connecting to %s:%d",
                server_ip.c_str(), server_port);

    ConnectionOptions connection_options;
    connection_options.host = server_ip.c_str();  // Required.
    connection_options.port = server_port; // Optional. The default port is 6379.
    connection_options.socket_timeout = std::chrono::milliseconds(REDIS_SOCKET_TIMEOUT);

    redis = new Redis(connection_options);

    try {
        // Setup subscriber and callback functions
        Subscriber sub = redis->subscriber();
        sub.on_message(msg_callback);
        sub.subscribe(channel);

        do {
            try {
                sub.consume();
            } catch (const TimeoutError &err) { // Ignoring timeout exception
            } catch (const Error &err) {
                 Logger::redis_client().error("Error consuming message: %s", err.what());
                 break;
            }
        } while(!redis_client_inst->terminate);
    } catch (const Error &err) {
        // TODO: Throw runtime error here?
        Logger::redis_client().error("Exception subscribing to channel %s: %s",
                channel.c_str(), err.what());
        if (redis) {
            delete redis;
        }
        return;
    }

    Logger::redis_client().debug("Out of redis thread loop. Terminating");

    if (redis) {
        delete redis;
    }
}

redis_client::redis_client(std::string server_ip, int server_port)
{
    Logger::redis_client().startup("Starting redis client");
    terminate = false;

    // Start task
    if (itti_inst->create_task(TASK_REDIS_CLIENT, redis_itti_task, nullptr)) {
        Logger::redis_client().error("Cannot create task TASK_REDIS_CLIENT");
        throw std::runtime_error("Cannot create task TASK_REDIS_CLIENT");
    }

    redis_thread = std::thread(redis_client_task, server_ip, server_port,
            std::string(REDIS_CHANNEL));

}

redis_client::~redis_client()
{
    Logger::redis_client().debug("Shutting down redis client");
    terminate = true;
    redis_thread.join();
}

void redis_client::process_redis_msg(itti_new_redis_msg &redis_msg)
{
    int rc;

    std::string msg = redis_msg.redis_msg;

    Document d;
    d.Parse(msg.c_str());

    if(!validate_pppd_json_msg(d)) {
        Logger::redis_client().error("Parsing error in received json message");
        return;
    }

    std::string event = d[PPPD_EVENT].GetString();

    // Only process session-acct-start events for now
    if(event.compare(SESSION_ACCT_START) != 0 && event.compare(SESSION_PRE_FINISHED) != 0 &&
      event.compare(SESSION_5G_REGISTER_START) != 0 && event.compare(SESSION_5G_REGISTER_STOP) != 0)
    {
        Logger::redis_client().debug("Ignoring message with event %s", event.c_str());
        return;
    }

    // Check event type and create appropriate type of message
    if(!event.compare(SESSION_ACCT_START)) {
        // Shared pointer for sereq message
        std::shared_ptr<itti_sxab_session_establishment_request> itti_sereq_ptr;

        // Create itti message to generate session establishment request
        itti_sxab_session_establishment_request *itti_sereq =
                new itti_sxab_session_establishment_request(TASK_REDIS_CLIENT, TASK_BNGC_PFCP);

        // Translate redis message to pfcp session establishment request
        rc = translate_ppp_to_pfcp_session_establishment(d, itti_sereq);

        if (rc == RETURNerror) {
            Logger::redis_client().error("Error parsing redis message to PFCP session establishment request");
            delete itti_sereq;
            return;
        }

        itti_sereq_ptr = std::shared_ptr<itti_sxab_session_establishment_request>(itti_sereq);

        // Send message to BNGC PFCP
        rc = itti_inst->send_msg(itti_sereq_ptr);
        if (rc != RETURNok) {
            Logger::redis_client().error("Error sending session establishment request ITTI msg to BNGC_PFCP");
        }
    } else if (!event.compare(SESSION_PRE_FINISHED)) { // Delete session
        // Shared pointer for session delete requsst message
        std::shared_ptr<itti_sxab_session_deletion_request> itti_sdreq_ptr;

        // Create itti message to generate session deletion request
        itti_sxab_session_deletion_request *itti_sdreq =
                new itti_sxab_session_deletion_request(TASK_REDIS_CLIENT, TASK_BNGC_PFCP);

        // Translate redis message to pfcp session establishment request
        rc = translate_ppp_to_pfcp_session_deletion(d, itti_sdreq);

        if (rc == RETURNerror) {
            Logger::redis_client().error("Error parsing redis message to PFCP session deletion request");
            delete itti_sdreq;
            return;
        }

        // Send message to BNGC PFCP
        itti_sdreq_ptr = std::shared_ptr<itti_sxab_session_deletion_request>(itti_sdreq);

        // Send message to BNGC PFCP
        rc = itti_inst->send_msg(itti_sdreq_ptr);
        if (rc != RETURNok) {
            Logger::redis_client().error("Error sending deletion establishment request ITTI msg to BNGC_PFCP");
        }
    }
    else if(!event.compare(SESSION_5G_REGISTER_START)) {
    /* Process registration message from accel-ppp */
        // Shared pointer for sereq message
        std::shared_ptr<itti_enbue_register_request> itti_reg_req_ptr;

        // Create itti message to generate session establishment request
        itti_enbue_register_request *itti_reg_req =
                new itti_enbue_register_request(TASK_REDIS_CLIENT, TASK_BNGC_ENBUE_APP);

        // Translate redis message to pfcp session establishment request
        rc = translate_ppp_to_5g_session_establishment(d, itti_reg_req);

        if (rc == RETURNerror) {
            Logger::redis_client().error("Error parsing redis message to ENBUE session establishment request");
            delete itti_reg_req;
            return;
        }

        itti_reg_req_ptr = std::shared_ptr<itti_enbue_register_request>(itti_reg_req);

        // Send message to BNGC ENBUE
        rc = itti_inst->send_msg(itti_reg_req_ptr);
        if (rc != RETURNok) {
            Logger::redis_client().error("Error sending session establishment request ITTI msg to BNGC_ENBUE");
        }
    }
    else if(!event.compare(SESSION_5G_REGISTER_STOP)) {
    /* Process registration message from accel-ppp */
        // Shared pointer for sereq message
        std::shared_ptr<itti_enbue_deregister_request> itti_dereg_req_ptr;

        // Create itti message to generate session establishment request
        itti_enbue_deregister_request *itti_dereg_req =
                new itti_enbue_deregister_request(TASK_REDIS_CLIENT, TASK_BNGC_ENBUE_APP);

        // Translate redis message to pfcp session establishment request
        rc = translate_ppp_to_5g_session_release (d, itti_dereg_req);

        if (rc == RETURNerror) {
            Logger::redis_client().error("Error parsing redis message to ENBUE session establishment request");
            delete itti_dereg_req;
            return;
        }

        itti_dereg_req_ptr = std::shared_ptr<itti_enbue_deregister_request>(itti_dereg_req);

        // Send message to BNGC ENBUE
        rc = itti_inst->send_msg(itti_dereg_req_ptr);
        if (rc != RETURNok) {
            Logger::redis_client().error("Error sending session establishment request ITTI msg to BNGC_ENBUE");
        }
    }
}

void redis_client::publish_redis_msg(itti_new_redis_pub_msg &redis_msg)
{
    int rc;
    std::string msg = redis_msg.redis_msg;

    Document d;
    d.Parse(msg.c_str());

    if (redis == nullptr) {
	Logger::redis_client().error("Error publishing message to PPP");
    }

    redis->publish(REDIS_PUB_CHANNEL, msg);
}

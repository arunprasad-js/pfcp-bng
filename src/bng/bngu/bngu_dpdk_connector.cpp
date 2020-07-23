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
#include "bngu_dpdk_connector.hpp"
#include "bngu_msg_handler.hpp"
#include "itti.hpp" // Task id and related itti objects

#include "AsioTelnetClient.h"

#include <string>
#include <chrono>

#define IP_PIPELINE_CTS ">"
#define MAX_TELNET_RETRIES 3

using namespace bngu;
using namespace std::chrono_literals;

extern itti_mw *itti_inst;
extern boost::asio::io_service io_service;
extern DPDKTelnetCLI *bngu_dpdk_upstream_inst;
extern DPDKTelnetCLI *bngu_dpdk_downstream_inst;

void bngu_dpdk_task(void *);

void bngu_dpdk_task(void *args_p)
{
    const task_id_t *task_id_ptr = (const task_id_t*)args_p;
    const task_id_t task_id = *task_id_ptr;
    Logger::bngu_dpdk().debug("Starting BNGU DPDK connector thread loop with task ID %d",
            task_id);

    bool upstream = task_id == TASK_DPDK_UPSTREAM;

    itti_inst->notify_task_ready(task_id);

    do {
        std::shared_ptr<itti_msg> shared_msg = itti_inst->receive_msg(task_id);
        auto *msg = shared_msg.get();
        switch (msg->msg_type)
        {
        case BNGU_DPDK_SEND_MESSAGE_REQUEST:
            if (itti_dpdk_send_msg_request* request =
                    dynamic_cast<itti_dpdk_send_msg_request*>(msg)) {
                Logger::bngu_dpdk().debug("[%s] Received DPDK send message request",
                        upstream ? "UL" : "DL");
                if(upstream) {
                    bngu_dpdk_upstream_inst->send_message(std::ref(*request));
                } else {
                    bngu_dpdk_downstream_inst->send_message(std::ref(*request));
                }
            }
            break;

        case TERMINATE:
            if (itti_msg_terminate *terminate = dynamic_cast<itti_msg_terminate*>(msg)) {
                Logger::bngu_dpdk().info("[%s] Received terminate message",
                        upstream ? "UL" : "DL");
                return;
            }
            break;
        default:
            Logger::bngu_dpdk().debug("[%s] Received msg with type %d",
                    upstream ? "UL" : "DL",
                    msg->msg_type);

        }
    } while((upstream && !bngu_dpdk_upstream_inst->terminate) ||
                (!upstream && !bngu_dpdk_downstream_inst->terminate));
    Logger::bngu_dpdk().debug("[%s] Terminate triggered", upstream ? "UL" : "DL");
}

// Callback function for messages received in upstream telnet client
void DPDKTelnetCLI::upstream_callback(const std::string& message)
{
    Logger::bngu_dpdk().debug("[UL] upstream_callback: Received TELNET message: %s",
            message.c_str());

    if(bngu_dpdk_downstream_inst == nullptr) {
        Logger::bngu_dpdk().warn("[UL] Callback called before bngu_dpdk_upstream_inst was instantiated");
        return;
    }

    if(message.find(IP_PIPELINE_CTS) != std::string::npos) {
        // Update ready_to_write to true and notify condition variable
        {
            std::lock_guard<std::mutex> lck(bngu_dpdk_upstream_inst->mtx);
            bngu_dpdk_upstream_inst->ready_to_write = true;
            bngu_dpdk_upstream_inst->retry_counter = 0;
        }
        bngu_dpdk_upstream_inst->cv.notify_all();
    }
}

// Callback function for messages received in downstream telnet client
void DPDKTelnetCLI::downstream_callback(const std::string& message)
{
    Logger::bngu_dpdk().debug("[DL] downstream_callback: Received TELNET message: %s",
            message.c_str());

    if(bngu_dpdk_downstream_inst == nullptr) {
        Logger::bngu_dpdk().warn("[DL] Callback called before bngu_dpdk_downstream_inst was instantiated");
        return;
    }

    if(message.find(IP_PIPELINE_CTS) != std::string::npos) {
         // Update ready_to_write to true and notify condition variable
        {
            std::lock_guard<std::mutex> lck(bngu_dpdk_downstream_inst->mtx);
            bngu_dpdk_downstream_inst->ready_to_write = true;
            bngu_dpdk_downstream_inst->retry_counter = 0;
        }
        bngu_dpdk_downstream_inst->cv.notify_all();
    }
}

// Callback function for a remote connection close
void DPDKTelnetCLI::close_callback()
{
    // TODO: Handle this and close local resources
    Logger::bngu_dpdk().debug("Disconnected");
}


DPDKTelnetCLI::DPDKTelnetCLI(std::string dest_ip, int dest_port, bool upstream)
{
    if (upstream) {
        Logger::bngu_dpdk().startup("[UL] Resolving upstream Telnet at %s:%d",
                dest_ip.c_str(), dest_port);
    } else {
        Logger::bngu_dpdk().startup("[DL] Resolving downstream Telnet at %s:%d",
                dest_ip.c_str(), dest_port);
    }

    ready_to_write = false;
    terminate = false;
    last_command = "\n";
    retry_counter = 0;

    this->dest_ip = dest_ip;
    this->dest_port = dest_port;
    this->upstream = upstream; // true for uplink, false for downlink

    if(upstream) {
        task_id = TASK_DPDK_UPSTREAM;
    } else {
        task_id = TASK_DPDK_DOWNSTREAM;
    }

    // Start task
    if (itti_inst->create_task(task_id, bngu_dpdk_task, &task_id)) {
        Logger::bngu_app().error("Cannot create task %d", task_id);
        throw std::runtime_error("Cannot create task");
    }

    Logger::bngu_dpdk().startup("[%s] Startup complete", upstream ? "UL" : "DL");
}

DPDKTelnetCLI::~DPDKTelnetCLI()
{
    Logger::bngu_dpdk().debug("[%s] Closing telnet client", upstream ? "UL" : "DL");
    if(telnet_client) {
        delete telnet_client;
    }
}

void DPDKTelnetCLI::close()
{
    std::unique_lock<std::mutex> lck(mtx);
    terminate = true;
    cv.notify_all();
}

void DPDKTelnetCLI::connect_telnet_client()
{
    try {
        tcp::resolver resolver(io_service);
        tcp::resolver::query query(dest_ip, std::to_string(dest_port));
        tcp::resolver::iterator iterator = resolver.resolve(query);

        Logger::bngu_dpdk().debug("[%s] Initializing telnet client",
                upstream ? "UL" : "DL");
        telnet_client = new AsioTelnetClient(io_service, iterator);

        if (upstream) {
            telnet_client->setReceivedSocketCallback(DPDKTelnetCLI::upstream_callback);
        } else {
            telnet_client->setReceivedSocketCallback(DPDKTelnetCLI::downstream_callback);
        }

        telnet_client->setClosedSocketCallback(DPDKTelnetCLI::close_callback);

    } catch (std::exception& e) {
        Logger::bngu_dpdk().error("[%s] Cannot instantiate telnet client. Exception: %s",
            upstream ? "UL" : "DL", e.what());
        telnet_client = nullptr;
    }
    // telnet_client = nullptr; // Deleting telnet connectivity for testing PFCP messages
}

void DPDKTelnetCLI::install_default_upstream_route(std::string upstream_route_ip_address,
        std::string bng_access_mac_address, std::string upstream_route_mac_address)
{

    Logger::bngu_dpdk().debug("[UL] Setting up default uplink route to %s %s/%s",
            upstream_route_ip_address.c_str(), bng_access_mac_address.c_str(),
            upstream_route_mac_address.c_str());

    std::string command = get_upstream_dpdk_default_route(upstream_route_ip_address,
            bng_access_mac_address, upstream_route_mac_address);

    send_telnet_command(command);
}

void DPDKTelnetCLI::send_message(itti_dpdk_send_msg_request &itti_message)
{
    std::string message = itti_message.dpdk_cli_msg;
    send_telnet_command(message);
}

void DPDKTelnetCLI::send_telnet_command(std::string message)
{
    // Appending \n to command, so it is executed
    message.append("\n");

    // Saving this command to resend if needed in case there's a timeout
    last_command = message;

    if (telnet_client == nullptr) {
        Logger::bngu_dpdk().warn("[%s] send_telnet_command: Telnet client in %s:%d was not initiated. Not sending message.",
                upstream ? "UL" : "DL", dest_ip.c_str(), dest_port);
        return;
    }

    // Waiting for ready_to_write to be true (this is only the case on the first message)
    wait_to_write();

    if (terminate) {
        Logger::bngu_dpdk().debug("[%s] send_telnet_command: Terminated. Aborting send",
                upstream ? "UL" : "DL");
        return;
    }

    Logger::bngu_dpdk().debug("[%s] send_telnet_command: Sending telnet message to %s:%d : %s",
                upstream ? "UL" : "DL", dest_ip.c_str(), dest_port, message.c_str());

    telnet_client->write(message);

    {
        // Set ready_to_write to false
        std::lock_guard<std::mutex> lck(mtx);
        ready_to_write = false;
    }

    // Waiting for response so we are sure our command was processed
    wait_to_write();
}

void DPDKTelnetCLI::wait_to_write()
{
    std::unique_lock<std::mutex> lck(mtx);
    while(!ready_to_write && !terminate) {
        // Waiting for one second to get a message. If timeout is reached, sends a blank message to telnet
        auto now = std::chrono::system_clock::now();
        if (cv.wait_until(lck, now + 1000ms) == std::cv_status::timeout) {
            if(!terminate) {
                if(retry_counter < MAX_TELNET_RETRIES) {
                    retry_counter++;
                    // send_blank_command();
                    resend_last_command();
                } else {
                    retry_counter = 0;
                    Logger::bngu_dpdk().error("[%s] wait_to_write: Number of resend attempts exceeded. Sending blank space and leaving function",
                            upstream ? "UL" : "DL");
                    send_blank_command();
                    return;
                }
            }
        }
    }
}

void DPDKTelnetCLI::send_blank_command()
{
    Logger::bngu_dpdk().debug("[%s] Sending a newline to telnet to avoid lock",
                upstream ? "UL" : "DL");
    telnet_client->write("\n");
}

void DPDKTelnetCLI::resend_last_command()
{
    Logger::bngu_dpdk().warn("[%s] Resending last command after wait lock timeout [%d/%d]: %s",
                upstream ? "UL" : "DL", retry_counter, MAX_TELNET_RETRIES,
                last_command.c_str());
    telnet_client->write(last_command);
}

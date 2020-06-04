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
#ifndef FILE_BNGU_DPDK_CONNECTOR_HPP_SEEN
#define FILE_BNGU_DPDK_CONNECTOR_HPP_SEEN

#include "AsioTelnetClient.h"
#include "itti_msg_dpdk.hpp"

#include <condition_variable>
#include <mutex>

namespace bngu {

class DPDKTelnetCLI {

private:
    void send_telnet_command(std::string message);

    static void upstream_callback(const std::string& message);
    static void downstream_callback(const std::string& message);
    static void close_callback();

    void wait_to_write();
    void send_blank_command();
    void resend_last_command();

    std::string last_command;
    int retry_counter;

    std::mutex mtx;
    std::condition_variable cv;
    bool ready_to_write;

    AsioTelnetClient *telnet_client;

    std::string dest_ip;
    int dest_port;

public:
    DPDKTelnetCLI(std::string dest_ip, int dest_port, bool direction);
    ~DPDKTelnetCLI();

    void connect_telnet_client();
    void install_default_upstream_route(std::string gateway_ip_address,
        std::string gateway_mac_address, std::string downstream_mac_address);

    void send_message(itti_dpdk_send_msg_request &itti_message);

    void close();

    bool upstream; // true for uplink, false for downlink
    task_id_t task_id; // Thread task id

    bool terminate;
};
}
#endif /* FILE_BNGU_DPDK_CONNECTOR_HPP_SEEN */

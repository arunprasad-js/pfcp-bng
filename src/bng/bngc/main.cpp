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
#include "itti.hpp"
#include "redis_client.hpp"
#include "thread_sched.hpp"

#include <boost/asio.hpp>
#include <iostream>
#include <signal.h>
#include <unistd.h> // pause()

#define DEBUG_LOG(x) std::cerr << __PRETTY_FUNCTION__ << ": " << x << std::endl

#define ITTI_SCHED_PRIORITY 85

using namespace bngc;
using namespace rapidjson;

itti_mw *itti_inst = nullptr; //  InTer Task Interface Master Worker (?)
bngc_app *bngc_app_inst = nullptr; // BNG control plane app instance
redis_client *redis_client_inst = nullptr; // Redis client instance
boost::asio::io_service io_service; // Thread mgmt
Document bngc_config;

// Signal handler
void my_app_signal_handler(int s){
    DEBUG_LOG("Caught signal " << s);
    Logger::system().startup("exiting");

    Logger::system().startup("Sending terminate msg to BNGC task %d", TASK_BNGC_APP);
    itti_inst->send_terminate_msg(TASK_BNGC_APP);
    itti_inst->wait_tasks_end();

    DEBUG_LOG("Freeing Allocated memory...");
    if (itti_inst) {
        delete itti_inst;
    }
    itti_inst = nullptr;
    DEBUG_LOG("ITTI memory done.");

    if (bngc_app_inst) {
        delete bngc_app_inst;
    }
    bngc_app_inst = nullptr;
    DEBUG_LOG("BNGC app memory done.");

    if (redis_client_inst) {
        delete redis_client_inst;
    }
    redis_client_inst = nullptr;
    DEBUG_LOG("Redis client memory done.");

    DEBUG_LOG("Freeing Allocated memory done");
    exit(0);
}

// Main function
int main(int argc, char **argv) {
    DEBUG_LOG("Hello world!");

    // Logger
    DEBUG_LOG("Initiating logger");
  	Logger::init("BNG CP");

    DEBUG_LOG("Instantiating signal handler");
    struct sigaction sigIntHandler;
    sigIntHandler.sa_handler = my_app_signal_handler;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;
    sigaction(SIGINT, &sigIntHandler, NULL);

    DEBUG_LOG("Reading configurations from file");
    if(argc > 1) {
        bngc_config = read_bngc_config_from_file(argv[1]);
    } else {
        bngc_config = read_bngc_config_from_file();
    }

    std::string bngc_ip = bngc_config[BNGC_IPV4_ADDRESS_OPTION].GetString();

    DEBUG_LOG("Instantiating ITTI");
    // Inter task Interface
  	itti_inst = new itti_mw();
  	util::thread_sched_params itti_timer_sched_params;
  	itti_timer_sched_params.sched_priority = ITTI_SCHED_PRIORITY;
  	itti_inst->start(itti_timer_sched_params);

    // BNGC application
    bngc_app_inst = new bngc_app();

    std::string redis_server_ip = bngc_config[REDIS_SERVER_IP_OPTION].GetString();
    int redis_server_port = bngc_config[REDIS_SERVER_PORT_OPTION].GetInt();

    // REDIS client
    redis_client_inst = new redis_client(redis_server_ip, redis_server_port);

  	pause();
    return 0;
}

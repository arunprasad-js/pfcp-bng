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
#include "itti.hpp"
#include "thread_sched.hpp"

#include <boost/asio.hpp>
#include <iostream>
#include <signal.h>
#include <unistd.h> // pause()

#define DEBUG_LOG(x) std::cerr << __PRETTY_FUNCTION__ << ": " << x << std::endl

#define ITTI_SCHED_PRIORITY 85

using namespace bngu;

itti_mw *itti_inst = nullptr; //  InTer Task Interface Master Worker (?)
bngu_app *bngu_app_inst = nullptr; // BNG user plane app instance
boost::asio::io_service io_service; // Thread mgmt
Document bngu_config;

// Signal handler
void my_app_signal_handler(int s){
    DEBUG_LOG("Caught signal " << s);
    Logger::system().startup("exiting");

    Logger::system().startup("Sending terminate msg to BNGU task %d", TASK_BNGU_APP);
    itti_inst->send_terminate_msg(TASK_BNGU_APP);
    itti_inst->wait_tasks_end();

    DEBUG_LOG("Freeing Allocated memory...");
    if (itti_inst) {
        delete itti_inst;
    }
    itti_inst = nullptr;
    DEBUG_LOG("ITTI memory done.");

    DEBUG_LOG("Stopping boost::io_service");
    io_service.stop();
    DEBUG_LOG("Done");

    if (bngu_app_inst) {
        delete bngu_app_inst;
    }
    bngu_app_inst = nullptr;
    DEBUG_LOG("BNGU app memory done.");

    DEBUG_LOG("Freeing Allocated memory done");
    exit(0);
}

// Main function
int main(int argc, char **argv) {
    DEBUG_LOG("Hello world!");

    // Logger
    DEBUG_LOG("Initiating logger");
  	Logger::init("BNG UP");

    DEBUG_LOG("Instantiating signal handler");
    struct sigaction sigIntHandler;
    sigIntHandler.sa_handler = my_app_signal_handler;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;
    sigaction(SIGINT, &sigIntHandler, NULL);

    // Read configuration from file
    DEBUG_LOG("Reading configurations from file");
    if(argc > 1) {
        bngu_config = read_bngu_config_from_file(argv[1]);
    } else {
        bngu_config = read_bngu_config_from_file();
    }

    DEBUG_LOG("Instantiating ITTI");
    // Inter task Interface
  	itti_inst = new itti_mw();
  	util::thread_sched_params itti_timer_sched_params;
  	itti_timer_sched_params.sched_priority = ITTI_SCHED_PRIORITY;
  	itti_inst->start(itti_timer_sched_params);

    // BNGU application
    bngu_app_inst = new bngu_app();

  	pause();
    return 0;
}

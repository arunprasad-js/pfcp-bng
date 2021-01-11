/*
* Copyright (c) 2020 Altran
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

#ifndef FILE_BNGC_ENBUE_MSG_HANDLER_HPP_SEEN
#define FILE_BNGC_ENBUE_MSG_HANDLER_HPP_SEEN

#include "itti_msg_enbue.hpp" // Reusing itti sxab messages for internal communication
#include "rapidjson/document.h"

#define PPPD_EVENT "event"
#define PPPD_CIRCUIT_ID "circuit_id"
#define PPPD_REMOTE_ID "remote_id"
#define SESSION_5G_REGISTER_START "register"
#define SESSION_5G_REGISTER_STOP "deregister"

#define DEFAULT_TRAFFIC_ENDPOINT_ID 1

namespace bngc_enbue {

int translate_ppp_to_5g_session_establishment(rapidjson::Document &d,
    itti_enbue_register_request *itti_sereq);

int translate_ppp_to_5g_session_release (rapidjson::Document &d,
    itti_enbue_deregister_request *itti_dereg_req);

}

#endif /* FILE_BNGC_ENBUE_MSG_HANDLER_HPP_SEEN */

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
#ifndef FILE_BNGC_APP_HPP_SEEN
#define FILE_BNGC_APP_HPP_SEEN

#include "itti_msg_sxab.hpp" // Reusing itti sxab messages for internal communication
#include <map>

#define DEFAULT_NAS_ID "nas1"

namespace bngc {

class bngc_app {

private:
    void process_bngu_endpoints();

public:
    explicit bngc_app();
    ~bngc_app();

    void handle_session_establishment_response(itti_sxab_session_establishment_response& response);
    void handle_session_deletion_response(itti_sxab_session_deletion_response& response);

    std::map<std::string, endpoint> bngu_endpoints;
};
}

#endif /* FILE_BNGC_APP_HPP_SEEN */

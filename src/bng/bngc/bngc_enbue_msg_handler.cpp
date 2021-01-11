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
#include "bngc_app.hpp"
#include "bngc_config.hpp"
#include "bngc_msg_handler.hpp"
#include "bngc_pfcp_association.hpp"
#include "3gpp_29.244.h" // PFCP protocol
#include "common_defs.h" // Return status
#include "itti.hpp" // itti_mw
#include "pfcp.hpp" // Default port
#include "uint_generator.hpp" // Generating TXIDs

#include "bngc_enbue_app.hpp"
#include "bngc_enbue_config.hpp"
#include "bngc_enbue_msg_handler.hpp"

#include <arpa/inet.h> // IP data structures
#include <functional> // Hash

using namespace bngc_enbue;
using namespace rapidjson;

extern bngc_enbue_app *bngc_enbue_app_inst;
extern itti_mw *itti_inst;
extern Document bngc_config;

int bngc_enbue::translate_ppp_to_5g_session_establishment(Document &d,
    itti_enbue_register_request *itti_reg_req)
{
    std::string circuit_id = d[PPPD_CIRCUIT_ID].GetString();
    std::string remote_id = d[PPPD_REMOTE_ID].GetString();
    std::string lineid_source = bngc_enbue_config[BNGC_ENBUE_LINEID_SOURCE_OPTION].GetString();
    std::string ifname = d[PPPD_CTRL_IFNAME].GetString();
    int pppoe_session_id_int = d[PPPD_PPPOE_SESSIONID].GetInt();
    char nai_userid[MAX_NAI_LEN];

    int circuit_id_len = circuit_id.size ();
    int remote_id_len = remote_id.size ();

    sprintf (nai_userid , "%s01%d%s02%d%s", lineid_source.c_str(),circuit_id_len, circuit_id.c_str(), remote_id_len, remote_id.c_str());

    Logger::bngc_enbue_app().debug("Circuit ID: %s", circuit_id.c_str());
    Logger::bngc_enbue_app().debug("Remote ID: %s", remote_id.c_str());
    Logger::bngc_enbue_app().debug("User name: %s", nai_userid);
    Logger::bngc_enbue_app().debug("IfName: %s", ifname.c_str());

    strcpy ((itti_reg_req->nai_userid), nai_userid);

    pdu_establish_connection *p = new (pdu_establish_connection);

    if (bngc_enbue_app_inst->find_conn_from_session (pppoe_session_id_int) == true)
    {
	Logger::bngc_enbue_app().debug("Session Id present in conn table ");
	return RETURNok;
    }

    p->session_id = pppoe_session_id_int;
    p->circuit_id = circuit_id;
    p->remote_id = remote_id;
    p->ifname = ifname;

    strncpy(p->nai_userid, nai_userid,(MAX_NAI_LEN-1));

    Logger::bngc_enbue_app().debug("NAI User Id : %s",p->nai_userid);

    std::shared_ptr<pdu_establish_connection> sp = std::shared_ptr<pdu_establish_connection>(p);
    bngc_enbue_app_inst->pdu_connections.push_back(sp);

    return RETURNok;
}


int bngc_enbue::translate_ppp_to_5g_session_release (Document &d,
    itti_enbue_deregister_request *itti_dereg_req)
{
    std::string circuit_id = d[PPPD_CIRCUIT_ID].GetString();
    std::string remote_id = d[PPPD_REMOTE_ID].GetString();
    std::string lineid_source = bngc_enbue_config[BNGC_ENBUE_LINEID_SOURCE_OPTION].GetString();
    int pppoe_session_id_int = d[PPPD_PPPOE_SESSIONID].GetInt();
    char nai_userid[MAX_NAI_LEN];

    int circuit_id_len = circuit_id.size ();
    int remote_id_len = remote_id.size ();

    Logger::bngc_enbue_app().debug("Circuit ID: %s", circuit_id.c_str());
    Logger::bngc_enbue_app().debug("Remote ID: %s", remote_id.c_str());

    sprintf (nai_userid , "%s01%d%s02%d%s", lineid_source.c_str(),circuit_id_len, circuit_id.c_str(), remote_id_len, remote_id.c_str());

    strcpy ((itti_dereg_req->nai_userid), nai_userid);
    Logger::bngc_enbue_app().debug("NAI User Id : %s",nai_userid);

    return RETURNok;
}

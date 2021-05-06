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
extern std::mutex conn_mtx;

int bngc_enbue::translate_ppp_to_5g_session_establishment(Document &d,
    itti_enbue_register_request *itti_reg_req)
{
    std::string circuit_id = d[PPPD_CIRCUIT_ID].GetString();
    std::string remote_id = d[PPPD_REMOTE_ID].GetString();
    std::string lineid_source = bngc_enbue_config[BNGC_ENBUE_LINEID_SOURCE_OPTION].GetString();
    std::string ifname = d[PPPD_CTRL_IFNAME].GetString();
    std::string iftype = d[PPPD_CTRL_IFTYPE].GetString();
    char nai_userid[MAX_NAI_LEN];

    int circuit_id_len = circuit_id.size ();
    int remote_id_len = remote_id.size ();

    sprintf (nai_userid , "%s01%d%s02%d%s", lineid_source.c_str(),circuit_id_len, circuit_id.c_str(), remote_id_len, remote_id.c_str());

    Logger::bngc_enbue_app().debug("Circuit ID: %s", circuit_id.c_str());
    Logger::bngc_enbue_app().debug("Remote ID: %s", remote_id.c_str());
    Logger::bngc_enbue_app().debug("User name: %s", nai_userid);
    Logger::bngc_enbue_app().debug("IfName: %s", ifname.c_str());

    strcpy ((itti_reg_req->nai_userid), nai_userid);

    if ((bngc_enbue_app_inst->is_nai_present (nai_userid)) != false)
    {
        Logger::bngc_enbue_app().debug("Session Id present in conn table ");
        return RETURNerror;
    }

    pdu_establish_connection *p = new (pdu_establish_connection);

    if (strcmp (iftype.c_str(), "pppoe") == 0)
    {
        int pppoe_session_id_int = d[PPPD_PPPOE_SESSIONID].GetInt();
        p->session_id = pppoe_session_id_int;
    }
    else if (strcmp (iftype.c_str(), "ipoe") == 0)
    {
	int xid = d[PPPD_DHCP_SESSIONID].GetInt();
        std::string session = d[PPPD_SESSIONID].GetString();
	p->session = session;
	p->xid = xid; 
    }

    p->iftype = iftype;
    p->circuit_id = circuit_id;
    p->remote_id = remote_id;
    p->ifname = ifname;

    strncpy(p->nai_userid, nai_userid,(MAX_NAI_LEN-1));

    Logger::bngc_enbue_app().debug("NAI User Id : %s",p->nai_userid);

    conn_mtx.lock();

    std::shared_ptr<pdu_establish_connection> sp = std::shared_ptr<pdu_establish_connection>(p);
    bngc_enbue_app_inst->pdu_connections.push_back(sp);

    conn_mtx.unlock();

    return RETURNok;
}

int bngc_enbue::translate_ppp_to_5g_session_release (Document &d,
    itti_enbue_deregister_request *itti_dereg_req)
{
    std::string circuit_id = d[PPPD_CIRCUIT_ID].GetString();
    std::string remote_id = d[PPPD_REMOTE_ID].GetString();
    std::string lineid_source = bngc_enbue_config[BNGC_ENBUE_LINEID_SOURCE_OPTION].GetString();
    char nai_userid[MAX_NAI_LEN];
    std::string ifname = d[PPPD_CTRL_IFNAME].GetString();
    std::string iftype = d[PPPD_CTRL_IFTYPE].GetString();
 
    int circuit_id_len = circuit_id.size ();
    int remote_id_len = remote_id.size ();

    Logger::bngc_enbue_app().debug("Circuit ID: %s", circuit_id.c_str());
    Logger::bngc_enbue_app().debug("Remote ID: %s", remote_id.c_str());

    sprintf (nai_userid , "%s01%d%s02%d%s", lineid_source.c_str(),circuit_id_len, circuit_id.c_str(), remote_id_len, remote_id.c_str());

    strcpy ((itti_dereg_req->nai_userid), nai_userid);
    Logger::bngc_enbue_app().debug("NAI User Id : %s",nai_userid);

    std::shared_ptr<bngc_enbue::pdu_establish_connection> ptr;

    if ((ptr = bngc_enbue_app_inst->find_conn_from_nai (nai_userid)) == NULL)
    {
        Logger::bngc_enbue_app().debug("Session Id not present in conn table ");
        return RETURNerror;
    }

    if (iftype != ptr->iftype)
    {
        Logger::bngc_enbue_app().debug("Ignoring the message due to iftype mismatch");
        return RETURNerror;
    }
    
    if (iftype == "pppoe")
    {
	int pppoe_session_id_int = d[PPPD_PPPOE_SESSIONID].GetInt();

	if (pppoe_session_id_int != ptr->session_id)
	{
	    Logger::bngc_enbue_app().debug("Ignoring the message due to session_id mismatch");
	    return RETURNerror;
	}
    }
    else
    {
	std::string session = d[PPPD_SESSIONID].GetString();

	if (session != ptr->session)
	{
	    Logger::bngc_enbue_app().debug("Ignoring the message due to session mismatch");
	    return RETURNerror;
	}
    }

    return RETURNok;
}

int bngc_enbue::translate_ppp_to_5g_pkt (Document &d,
    itti_enbue_packet *itti_pkt)
{
    const Value &a = d[SESSION_5G_PACKET];
    std::string circuit_id = d[PPPD_CIRCUIT_ID].GetString();
    std::string remote_id = d[PPPD_REMOTE_ID].GetString();
    std::string lineid_source = bngc_enbue_config[BNGC_ENBUE_LINEID_SOURCE_OPTION].GetString();
    char nai_userid[MAX_NAI_LEN];
    int circuit_id_len = circuit_id.size ();
    int remote_id_len = remote_id.size ();

    assert(a.IsArray());
    for (SizeType i = 0; i < a.Size(); i++) // rapidjson uses SizeType instead of size_t.
    {
	itti_pkt->pkt[i] = (char )a[i].GetInt();
    }

    itti_pkt->len = a.Size();

    itti_pkt->siaddr = d[PPPD_SIADDR].GetInt();
    itti_pkt->giaddr = d[PPPD_GIADDR].GetInt();

    Logger::bngc_enbue_app().debug("Circuit ID: %s", circuit_id.c_str());
    Logger::bngc_enbue_app().debug("Remote ID: %s", remote_id.c_str());

    sprintf (nai_userid , "%s01%d%s02%d%s", lineid_source.c_str(), circuit_id_len, 
	    circuit_id.c_str(), remote_id_len, remote_id.c_str());
    strcpy ((itti_pkt->nai_userid), nai_userid);

    Logger::bngc_enbue_app().debug("NAI User Id : %s",nai_userid);

    return RETURNok;
}

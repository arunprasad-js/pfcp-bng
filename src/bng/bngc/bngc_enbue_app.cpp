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
#include "bngc_pfcp.hpp"
#include "itti.hpp"
#include "logger.hpp"
#include "thread_sched.hpp"
#include <sys/epoll.h>

#include "bngc_enbue_app.hpp"
#include "bngc_enbue_config.hpp"
#include "bngc_enbue_msg_handler.hpp"

#define BNGC_ENBUE_SCHED_PRIORITY 84
#define BNGC_PFCP_SCHED_PRIORITY 84

using namespace bngc_enbue;
using namespace bngc;
using namespace rapidjson;

extern bngc_enbue_app *bngc_enbue_app_inst;
extern itti_mw *itti_inst;
extern Document bngc_enbue_config;

util::thread_sched_params bngc_enbue_sched_params; // BNGC ENBUE App thread parameters
util::thread_sched_params bngc_enbue_rx_sched_params; // BNGC ENBUE App thread parameters
int32_t pollSet;
std::mutex mtx;

void bngc_enbue_app_task(void*); // Message loop task
void bngc_enbue_rx_app(void *);
extern void construct_message (std::string ip_addr, int session_id, std::string ifname);

int32_t bngc_enbue_timedwait (struct  epoll_event *pFdCtxts)
{
    int32_t  nfd = 0;
    int i = 0;

    while(1)
    {
        if ((nfd = epoll_wait (pollSet, pFdCtxts, 64, 1)) < 0)
	{
	    return nfd;
	}

	for(i = 0; i < nfd; i++)
	{
            if ((pFdCtxts + i)->events & EPOLLIN)
	    {
		return (pFdCtxts + i)->data.fd;
	    }
	}

	return nfd;
    }

    return nfd;
}

uint32_t bngc_enbue_register_fd (int32_t fd)
{
    struct epoll_event  ev;

    Logger::bngc_enbue_app().debug ("Entering %s",__func__);
    memset (&ev, 0, sizeof(struct epoll_event));

    /* Set the Event */
    ev.events = EPOLLIN|EPOLLHUP|EPOLLERR|0x2000;
    ev.data.fd = fd;

    Logger::bngc_enbue_app().debug ("Registering FD [%d] ", fd);
    /* Add the Event */
    if (epoll_ctl (pollSet, EPOLL_CTL_ADD, fd, &ev) < 0) {
	if(errno == EEXIST)
	{
	    /* Igonre */
	    return RETURNok;
	}

	Logger::bngc_enbue_app().error ("Registering failed for FD [%d] ",
		fd);

	return RETURNerror;
    }
    Logger::bngc_enbue_app().debug ("Exiting %s",__func__);
    return RETURNok;
}

uint32_t bngc_enbue_deregister_fd (int32_t fd)
{
    struct epoll_event  ev;

    if (epoll_ctl(pollSet, EPOLL_CTL_DEL, fd, &ev) < 0)
    {
	Logger::bngc_enbue_app().error ("Deregistering failed for FD [%d] ", fd);
        return RETURNerror;
    }

    Logger::bngc_enbue_app().error ("Deregistering success for FD [%d] ", fd);

    return RETURNok;
}

std::string convert_to_string(char* a)
{ 
    std::string s = a; 
    return s; 
} 

int
bngc_enbue_process_response_msg (uint32_t sock_fd)
{
    uint32_t                length;
    uint16_t                indx=0;
    uint8_t                 buffer[4096];
    int                     rc = 0;
    int                     bytesRead = 0;
    char                    respImsi[SIM_MAX_NAI_USERNAME_LEN];
    tEnbSimAttachResp       attResp;
    struct sockaddr_in      ipAddress;
    lte_ip_address_t        ueIPAddress[15];
    sim_ext_header_t        hdr;
    tEnbSimFlowGenResp     *pFlowResMsg = NULL;
    char                    str[INET_ADDRSTRLEN];

    bytesRead = recv (sock_fd, &hdr, sizeof(sim_ext_header_t), MSG_PEEK);
    if (bytesRead > 0) 
    {
	length = hdr.length;
	memset (buffer,0x00,4096);
	bytesRead = recv(sock_fd, (void *)(buffer), length, 0);
	if(bytesRead > 0) 
	{
	    Logger::bngc_enbue_app().debug ("Message received on Socket: %d, bytes %d",
		    sock_fd, bytesRead);

	    pFlowResMsg = ( tEnbSimFlowGenResp *)buffer;

	    if (pFlowResMsg != NULL)
	    {
		if (EXT_SUCCESS == pFlowResMsg->result)
		{
		    memset(respImsi,0,SIM_MAX_NAI_USERNAME_LEN);
		    if(pFlowResMsg->supiFormat > 0)
		    {
			memcpy(respImsi, pFlowResMsg->userName, strlen(pFlowResMsg->userName));
		    }

		    if(pFlowResMsg->procId == enbSimPdnConnReq)
		    {
			for (indx =0 ; indx < 15; indx ++)
			{
			    ipAddress.sin_addr.s_addr=htonl(pFlowResMsg->ueIPAddress[indx].ip_addr_u.ip4_addr.addr);
			    if (0 != pFlowResMsg->ueIPAddress[indx].ip_addr_u.ip4_addr.addr)
			    {
				ipAddress.sin_addr.s_addr=htonl(pFlowResMsg->ueIPAddress[indx].ip_addr_u.ip4_addr.addr);
                                std::string imsi = convert_to_string (respImsi);
				inet_ntop(AF_INET, &(ipAddress.sin_addr), str, INET_ADDRSTRLEN);
                                std::string ip_addr = convert_to_string (str);
				Logger::bngc_enbue_app().debug ("IP Address : %s NAI_String : %s Tunnel ID: 0x%X ",ip_addr.c_str(), imsi.c_str(), pFlowResMsg->tunnelId[indx]);

				int qfi = pFlowResMsg->qfi;
				int tunnelid = htonl (pFlowResMsg->tunnelId[indx]);
                                bngc_enbue_app_inst->update_pdu_info_from_imsi (respImsi, ip_addr, tunnelid, qfi);
			    }
			}
		    }
		    else if (pFlowResMsg->procId == enbSimAttachReq)
		    {
			Logger::bngc_enbue_app().debug ("5G REGISTERATION Successful for : %s  ",respImsi);
			rc = bngc_enbue_app_inst->bngc_enbue_form_pdu_request (respImsi);
			if (rc != RETURNok)
			{
			    Logger::bngc_enbue_app().error ("%s: bngc_enbue_form_pdu_request failed", __func__ );
			    return rc;
			}
		    }
		    else if (pFlowResMsg->procId == enbSimDelPdnReq)
		    {
			Logger::bngc_enbue_app().debug ("5G PDU_RELEASE Successful for : %s", __func__, respImsi);
			rc = bngc_enbue_app_inst->bngc_enbue_form_detach_request (respImsi);
			if (rc != RETURNok)
			{
			    Logger::bngc_enbue_app().error ("%s: bngc_enbue_form_pdu_request failed", __func__ );
			    return rc;
			}
		    }
		}
		else
		{
		    return RETURNerror; 
		}
	    }

	}
    }
    else if (bytesRead == 0)
    {
        bngc_enbue_deregister_fd (sock_fd);
    }

    return RETURNok;
}

void bngc_enbue_rx_app(void *)
{
    uint32_t nfd = 0;
    struct  epoll_event *event;
    const task_id_t task_id = TASK_BNGC_ENBUE_RX_APP;

    Logger::bngc_enbue_app().debug("Starting BNGC ENBUE RX thread loop with task ID %d", TASK_BNGC_ENBUE_RX_APP);

    bngc_enbue_rx_sched_params.sched_priority = BNGC_ENBUE_SCHED_PRIORITY;
    bngc_enbue_rx_sched_params.apply(task_id, Logger::bngc_enbue_app());

    itti_inst->notify_task_ready(task_id);

    event = (struct  epoll_event *)calloc(64, sizeof(struct  epoll_event));

    if (event == NULL)
    {
	Logger::bngc_enbue_app().debug("Allocating memory failed ");
	return;
    }

    /* Create the Epoll Set */
    if ((pollSet = epoll_create(1)) < 0 ) 
    {
        perror( "epoll_create" );
	Logger::bngc_enbue_app().debug("epoll_create failed ");
	return;
    }

    for( ; ; ) 
    {
	nfd = 0;
	nfd = bngc_enbue_timedwait (event);
	mtx.lock ();
	if (nfd > 0) {
	    bngc_enbue_process_response_msg (nfd);
	}
	mtx.unlock ();
    }
    return;
}

int bngc_enbue_app:: bngc_enbue_ngap_proc ()
{
    int rc = RETURNerror;

    mtx.lock ();

    Logger::bngc_enbue_app().debug ("Initiate 5G NGAP PROCEDURE ");

    rc = ecgi_add_conf ();
    if (rc != RETURNok)
    {
	Logger::bngc_enbue_app().error ("%s: ecgi_add_conf failed", __func__ );
	mtx.unlock ();
	return rc;
    }
    Logger::bngc_enbue_app().debug ("%s: ecgi_add_conf success", __func__ );

    rc = tai_conf_add ();
    if (rc != RETURNok)
    {
	Logger::bngc_enbue_app().error ("%s: tai_conf_add failed", __func__ );
	mtx.unlock ();
	return rc;
    }
    Logger::bngc_enbue_app().debug ("%s: tai_conf_add success", __func__ );

    rc = amf_instance_conf ();
    if (rc != RETURNok)
    {
	Logger::bngc_enbue_app().error ("%s: amf_instance_conf failed", __func__ );
	mtx.unlock ();
	return rc;
    }
    Logger::bngc_enbue_app().debug ("%s: amf_instance_conf success", __func__ );

    rc = enb_instance_add ();
    if (rc != RETURNok)
    {
	Logger::bngc_enbue_app().error ("%s: enb_instance_add failed", __func__ );
	mtx.unlock ();
	return rc;
    }
    Logger::bngc_enbue_app().debug ("%s: enb_instance_add success", __func__ );

    Logger::bngc_enbue_app().debug ("5G NGAP PROCEDURE Completed ");

    mtx.unlock ();
    return rc;
}

int bngc_enbue_app::
bngc_enbue_register (itti_enbue_register_request &ser)
{
    int rc = RETURNerror;

    mtx.lock ();

    rc = bngc_enbue_form_attach_request (ser.nai_userid);
    if (rc != RETURNok)
    {
	Logger::bngc_enbue_app().error ("%s: bngc_enbue_form_attach_request failed", __func__ );
        mtx.unlock ();
	return rc;
    }

    mtx.unlock ();
    return rc;
}

int bngc_enbue_app::
bngc_enbue_deregister (itti_enbue_deregister_request &ser)
{
    int rc = RETURNerror;

    mtx.lock ();

    rc = bngc_enbue_form_pdu_release (ser.nai_userid); 
    if (rc != RETURNok)
    {
	Logger::bngc_enbue_app().error ("%s: bngc_enbue_form_pdu_release failed", __func__ );
        mtx.unlock ();
	return rc;
    }

    Logger::bngc_enbue_app().debug ("%s: bngc_enbue_form_pdu_release success", __func__ );

    mtx.unlock ();

    return rc;
}


int bngc_enbue_app::
OpenConnection (const char *address, int port)
{
    struct sockaddr_in theiraddr;
    struct in_addr  ip_addr = {};
    unsigned char buf_in_addr[sizeof(struct in6_addr)];

    if (inet_pton (AF_INET, address, buf_in_addr) == 1) 
    {
       memcpy (&ip_addr, buf_in_addr, sizeof (struct in_addr));
    }

    Logger::bngc_enbue_app().debug ("OpenConnection: connect for "
		"(%s:%u)", address, port);
	
    if((bngc_enbue_sock = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
	Logger::bngc_enbue_app().debug ("OpenConnection: Socket creation Fail");
	perror("socket");
	return -1;
    }

    memset(&(theiraddr), '\0', sizeof(theiraddr));

    theiraddr.sin_family = AF_INET;
    theiraddr.sin_port = htons (port);
    theiraddr.sin_addr.s_addr = ip_addr.s_addr;

    memset(&(theiraddr.sin_zero), '\0', 8);

    if(connect(bngc_enbue_sock, (struct sockaddr*)&theiraddr, 
		sizeof(struct sockaddr)) == -1)
    {
	Logger::bngc_enbue_app().debug ("OpenConnection: connect failed for "
		"(%s:%u) ", address, port);
	perror("connect");
	return -1;
    }

    bngc_enbue_register_fd (bngc_enbue_sock);

    if (bngc_enbue_sock > 0)
    {
	if (bngc_enbue_ngap_proc () != RETURNok)
	{
	    Logger::bngc_enbue_app().debug ("OpenConnection: Ngap Procedure failed !!");
	    return -1;
	}
    }

    return bngc_enbue_sock;
}

bool bngc_enbue_app::find_conn_from_session (int session_id)
{
    for (auto it : pdu_connections) {
	if(it->session_id == session_id) {
	    return true; 
	}
    }
    return false;
}

void bngc_enbue_app::update_pdu_info_from_imsi (char *nai_str, std::string ip_addr, int ngc_tunnel, int qfi)
{
    for (auto it : pdu_connections) {
	if(strcmp (it->nai_userid, nai_str) == 0) {
		it->ip_addr = ip_addr;
		it->ngc_tunnel = ngc_tunnel;
		it->qfi = qfi;
		construct_message (ip_addr, it->session_id, it->ifname);
	}
    }
}

int bngc_enbue_app::get_tunnel_id (int session_id)
{
    for (auto it : pdu_connections) {
	    if (it->session_id == session_id)
	        return it->ngc_tunnel;
    }

    return 0;
}

int bngc_enbue_app::get_qfi_id (int session_id)
{
    for (auto it : pdu_connections) {
	    if (it->session_id == session_id)
	        return it->qfi;
    }

    return 0;
}

void bngc_enbue_app::delete_pdu_info (char *nai_str)
{
#if 0
    std::vector<std::shared_ptr<pdu_establish_connection>>::iterator iter; 

    iter = pdu_connections.begin();

    for (auto it : pdu_connections) {

	if (iter == pdu_connections.end())
	    break;

	if(strcmp (it->nai_userid, nai_str) == 0) {
	    bngc_enbue_app_inst->pdu_connections.erase (iter);
	}
	iter ++;
    }
#endif

    for (std::vector<std::shared_ptr<pdu_establish_connection>>::iterator it = pdu_connections.begin();
	    it < pdu_connections.end(); ++it) {
	if (strcmp ((*it)->nai_userid, nai_str) == 0) {
	    bngc_enbue_app_inst->pdu_connections.erase (it);
	    break;
	}
    }
}

void bngc_enbue_app::print_list ()
{
    for (auto it : pdu_connections) {
     Logger::bngc_enbue_app().debug ("NAI_String: %s | Session ID: %d | IP Address: %s | Tunnel ID: 0x%X ",it->nai_userid, it->session_id, it->ip_addr.c_str(), it->ngc_tunnel);
  } 
}

int bngc_enbue_app:: tai_conf_add ()
{
    int rc = RETURNerror; 
    int len = 0, num_bytes = -1;
    char buffer[MAX_DATA_SIZE];
    tTaiConf taiConfVar;
    flow_msg_t *msg = NULL;

    memset(&taiConfVar, 0, sizeof(tTaiConf));

    len = (sizeof(flow_msg_t) + sizeof(tTaiConf) - 1);

    msg = (flow_msg_t *) malloc(len);

    if( NULL == msg )
    {
	Logger::bngc_enbue_app().debug ("tai_conf_add memory allocation failed");
	return rc; 
    }

    memset (msg, 0, len);
    /* filling header with api Id and action */
    msg->hdr.apiId = taiConf;
    msg->hdr.action = SIM_MGMT_ACTION_ADD;
    msg->hdr.length = len;

    taiConfVar.index = bngc_enbue_config[BNGC_ENBUE_TAI_INDEX_OPTION].GetInt();

    strcpy((char *)taiConfVar.tai.plmn_id.octets, bngc_enbue_config[BNGC_ENBUE_TAI_PLMN_ID_OPTION].GetString()); 
    std::string plm_string = bngc_enbue_config[BNGC_ENBUE_TAI_PLMN_ID_OPTION].GetString();

    if(5 == plm_string.size()) 
    {
	taiConfVar.tai.plmn_id.num_mnc_digits = 2;
    }
    else if(6 == plm_string.size()) 
    {
	taiConfVar.tai.plmn_id.num_mnc_digits = 3;
    }

    taiConfVar.tai.tac = bngc_enbue_config[BNGC_ENBUE_TAI_TAC_OPTION].GetInt();

    taiConfVar.mmeIndex   = bngc_enbue_config[BNGC_ENBUE_TAI_MME_OPTION].GetInt();
    taiConfVar.plmnCount  = bngc_enbue_config[BNGC_ENBUE_TAI_PLMN_COUNT_OPTION].GetInt();
    taiConfVar.tacCount   = bngc_enbue_config[BNGC_ENBUE_TAC_COUNT_OPTION].GetInt();
    taiConfVar.nbType     = bngc_enbue_config[BNGC_ENBUE_TAI_NB_OPTION].GetInt();
    taiConfVar.nbIdLength = bngc_enbue_config[BNGC_ENBUE_TAI_NB_LEN_OPTION].GetInt();

    memcpy(msg->payload, &taiConfVar, sizeof(tTaiConf));

    /* send request to eNodeB simulator */
    if(send(bngc_enbue_sock, (char*)msg, len, 0) < 0)
    {
	free(msg);
	return rc; 
    }

    /* receive response from eNodeB simulator */
    if((num_bytes = recv(bngc_enbue_sock, buffer, sizeof(buffer), 0)) == -1)
    {
	free(msg);
	return rc; 
    }

    tEnbSimGenResp *buff = (tEnbSimGenResp*)((flow_msg_t*)buffer)->payload;
    Logger::bngc_enbue_app().debug("Error Code: %d, Result: %d ", buff->errCode, buff->result);
    free(msg);
    return RETURNok; 
}

int bngc_enbue_app:: amf_instance_conf ()
{
    int rc = RETURNerror; 
    int len = 0, num_bytes = -1;
    char buffer[MAX_DATA_SIZE];
    tMmeInstanceConf mmeInstanceConfVar;  /* payload variable */
    flow_msg_t *msg = NULL;

    memset(&mmeInstanceConfVar, 0, sizeof(tMmeInstanceConf));

    len = (sizeof(flow_msg_t) + sizeof(tMmeInstanceConf) - 1);

    msg = (flow_msg_t *) malloc(len);

    if (NULL == msg)
    {
	Logger::bngc_enbue_app().error ("amf_instance_conf memory allocation failed");
	return rc; 
    }

    memset (msg, 0, len);

    /* filling header with api Id and action */
    msg->hdr.apiId = amfInstanceConf; 
    msg->hdr.action = SIM_MGMT_ACTION_ADD;
    msg->hdr.length = len;

    /* filling payload with parameters */
    if((bngc_enbue_config[BNGC_ENBUE_AMF_INST_OPTION].GetInt()) < MME_INSTANCE_INDEX_MIN ||
       (bngc_enbue_config[BNGC_ENBUE_AMF_INST_OPTION].GetInt()) > MME_INSTANCE_INDEX_MAX)
    {
	free(msg);
	return rc; 
    }

    mmeInstanceConfVar.index = bngc_enbue_config[BNGC_ENBUE_AMF_INST_OPTION].GetInt(); 
    mmeInstanceConfVar.sctpIpAddress.ip_addr_type = bngc_enbue_config[BNGC_ENBUE_AMF_ADDR_TYPE_OPTION].GetInt();

    if (LTE_IP_ADDRESS_IPV4== mmeInstanceConfVar.sctpIpAddress.ip_addr_type) 
    {
	mmeInstanceConfVar.sctpIpAddress.ip_addr_u.ip4_addr.addr = inet_addr (bngc_enbue_config[BNGC_ENBUE_AMF_SCTP_ADDR_OPTION].GetString()); 
    }
    else
    {
	free(msg);
	return rc; 
    }

    mmeInstanceConfVar.sctpPort = bngc_enbue_config[BNGC_ENBUE_AMF_SCTP_PORT_OPTION].GetInt(); 
    memcpy(msg->payload, &mmeInstanceConfVar, sizeof(tMmeInstanceConf));

    /* send request to eNodeB simulator */
    if(send(bngc_enbue_sock, (char*)msg, len, 0) < 0)
    {
	free(msg);
	return rc; 
    }

    /* receive response from eNodeB simulator */
    if((num_bytes = recv(bngc_enbue_sock, buffer, sizeof(buffer), 0)) == -1)
    {
	free(msg);
	return rc; 
    }

    tEnbSimGenResp *buff = (tEnbSimGenResp*)((flow_msg_t*)buffer)->payload;
    Logger::bngc_enbue_app().debug("Error Code: %d, Result: %d ", buff->errCode, buff->result);
    free(msg);
    return RETURNok; 
}

int bngc_enbue_app::ecgi_add_conf ()
{
    int          rc = RETURNerror; 
    int          len = 0, num_bytes = -1;
    char         buffer[MAX_DATA_SIZE];
    ecgi_conf_t  ecgiConfVar; 
    flow_msg_t   *msg = NULL;

    memset(&ecgiConfVar, 0, sizeof(ecgi_conf_t));

    /* filling payload with parameters */
    if( bngc_enbue_config[BNGC_ENBUE_ECGI_CONF_OPTION].GetInt() < ECGI_CONF_INDEX_MIN ||
        bngc_enbue_config[BNGC_ENBUE_ECGI_CONF_OPTION].GetInt() > ECGI_CONF_INDEX_MAX)
    {
	return rc; 
    }

    ecgiConfVar.index = bngc_enbue_config[BNGC_ENBUE_ECGI_CONF_OPTION].GetInt();
    strcpy((char *)ecgiConfVar.ecgi.plmn_id.octets, bngc_enbue_config[BNGC_ENBUE_ECGI_PLMN_ID_OPTION].GetString()); 
    std::string plm_string = bngc_enbue_config[BNGC_ENBUE_ECGI_PLMN_ID_OPTION].GetString();

    if(5 == plm_string.size()) 
    {
	ecgiConfVar.ecgi.plmn_id.num_mnc_digits = 2;
    }
    else if(6 == plm_string.size()) 
    {
	ecgiConfVar.ecgi.plmn_id.num_mnc_digits = 3;
    }

    strncpy((char *)ecgiConfVar.ecgi.eci.bytes, bngc_enbue_config[BNGC_ENBUE_ECGI_ECI_ID_OPTION].GetString(), LTE_ECI_LEN);
    ecgiConfVar.taiIndex = bngc_enbue_config[BNGC_ENBUE_ECGI_TAI_OPTION].GetInt();
    strcpy((char *)ecgiConfVar.ecgi.plmn_id.octets, bngc_enbue_config[BNGC_ENBUE_ECGI_PLMN_ID_OPTION].GetString());
    ecgiConfVar.taiIndex = bngc_enbue_config[BNGC_ENBUE_TAI_INDEX_OPTION].GetInt();

    len = (sizeof(flow_msg_t) + sizeof(ecgi_conf_t) - 1);

    msg = (flow_msg_t *) malloc (len);

    if (NULL == msg)
    {
	Logger::bngc_enbue_app().error ("ecgi_add_conf memory allocation failed");
	return rc; 
    }

    memset (msg, 0, len);

    msg->hdr.apiId = ecgiConf;
    msg->hdr.action = SIM_MGMT_ACTION_ADD;
    msg->hdr.length = len;

    memcpy (msg->payload, &ecgiConfVar, sizeof (ecgi_conf_t));

    /* send request to eNodeB simulator */
    if(send(bngc_enbue_sock, (char*)msg, len, 0) < 0)
    {
	free (msg);
	return rc; 
    }

    /* receive response from eNodeB simulator */
    if((num_bytes = recv(bngc_enbue_sock, (buffer), sizeof(buffer), 0)) == -1)
    {
	free (msg);
	return rc;
    }

    tEnbSimGenResp *buff = (tEnbSimGenResp*)((flow_msg_t*)buffer)->payload;
    Logger::bngc_enbue_app().debug("Error Code: %d, Result: %d ", buff->errCode, buff->result);
    free (msg);

    return RETURNok; 
}

int bngc_enbue_app::enb_instance_add ()
{
    int       rc = RETURNerror; 
    int       len = 0;
    int       num_bytes = -1;
    char      buffer[MAX_DATA_SIZE];
    tEnbInstanceConf enbInstanceConfVar;  /* api for enb conf add */
    flow_msg_t *msg = NULL;

    len = (sizeof(flow_msg_t) + sizeof(tEnbInstanceConf) - 1);

    msg = (flow_msg_t *) malloc (len);

    if (NULL == msg)
    {
	Logger::bngc_enbue_app().error ("enb_instance_add memory allocation failed");
	return rc; 
    }

    memset(&enbInstanceConfVar, 0, sizeof(tEnbInstanceConf));
    memset(msg, 0, len);

    /* filling header with api Id and action */
    msg->hdr.apiId = enbInstanceConf;
    msg->hdr.action = SIM_MGMT_ACTION_ADD;
    msg->hdr.length = len;

    /* filling payload with parameters */
    if(bngc_enbue_config[BNGC_ENBUE_INST_INDEX_OPTION].GetInt() < ENODEB_INSTANCE_INDEX_MIN ||
       bngc_enbue_config[BNGC_ENBUE_INST_INDEX_OPTION].GetInt() > ENODEB_INSTANCE_INDEX_MAX)
    {
	free (msg);
	return rc; 
    }

    enbInstanceConfVar.index = bngc_enbue_config[BNGC_ENBUE_INST_INDEX_OPTION].GetInt();
    enbInstanceConfVar.sctpIpAddress[0].ip_addr_type = bngc_enbue_config[BNGC_ENBUE_ADDR_TYPE_OPTION].GetInt();
    enbInstanceConfVar.sctpAddCount = 1; 
    enbInstanceConfVar.sctpPort = bngc_enbue_config[BNGC_ENBUE_SCTP_PORT_OPTION].GetInt();

    if(LTE_IP_ADDRESS_IPV4 == bngc_enbue_config[BNGC_ENBUE_ADDR_TYPE_OPTION].GetInt())
    {
	enbInstanceConfVar.sctpIpAddress[0].ip_addr_u.ip4_addr.addr =inet_addr (bngc_enbue_config[BNGC_ENBUE_IP_ADDR_OPTION].GetString()); 
    }
    else
    {
	free (msg);
	return rc; 
    }

    if((bngc_enbue_config[BNGC_ENBUE_TAI_INDEX_OPTION].GetInt() < ENODEB_INSTANCE_TAI_INDEX_MIN) ||
       (bngc_enbue_config[BNGC_ENBUE_TAI_INDEX_OPTION].GetInt() > ENODEB_INSTANCE_TAI_INDEX_MAX))
    {
	free (msg);
	return rc; 
    }

    enbInstanceConfVar.taiIndex = bngc_enbue_config[BNGC_ENBUE_TAI_INDEX_OPTION].GetInt();
    enbInstanceConfVar.groupId = bngc_enbue_config[BNGC_ENBUE_GROUP_ID_OPTION].GetInt();

    memcpy(enbInstanceConfVar.isHenbId,bngc_enbue_config[BNGC_ENBUE_HENB_ID_OPTION].GetString(),
 	    strlen (bngc_enbue_config[BNGC_ENBUE_HENB_ID_OPTION].GetString()));

    memcpy (msg->payload, &enbInstanceConfVar, sizeof (tEnbInstanceConf));

   /* send request to eNodeB simulator */
    if(send(bngc_enbue_sock, (char*)msg, len, 0) < 0)
    {
	free (msg);
	return rc; 
    }

    /* receive response from eNodeB simulator */
    if((num_bytes = recv(bngc_enbue_sock, buffer, sizeof(buffer), 0)) == -1)
    {
	free (msg);
	return rc; 
    }

    tEnbSimGenResp *buff = (tEnbSimGenResp*)((flow_msg_t*)buffer)->payload;
    if (buff->errCode != ENBSIM_NO_ERROR)
    {
	rc = RETURNerror; 
    }
    else
    {
	rc = RETURNok; 
    }
    free (msg);
    Logger::bngc_enbue_app().debug("Error Code: %d, Result: %d ", buff->errCode, buff->result);

    return rc; 
}

int bngc_enbue_app::
bngc_enbue_form_attach_request (char *nai_userid)
{
    int                 len = 0;
    int                 bytesSent = 0;
    int                 rc = RETURNerror;
    int                 num_bytes = -1;
    char                buffer[MAX_DATA_SIZE];
    tEnbSimAttachReq    attReq;
    flow_msg_t          *msg = NULL;
 
    Logger::bngc_enbue_app().debug ("Sending 5G REGISTERATION for %s ", nai_userid);

    len = (sizeof (flow_msg_t) + sizeof (tEnbSimAttachReq) - 1);

    msg = (flow_msg_t *) malloc (len);
    if (NULL == msg)
    {
	Logger::bngc_enbue_app().error ("bngc_enbue_form_attach_request memory allocation failed");
	return rc; 
    }

    memset(&attReq,0,sizeof(attReq));
    memset(msg, 0, len);

    msg->hdr.apiId = enbSimAttachReq;
    msg->hdr.proc_index = enbSimAttachReq;
    msg->hdr.action = LTE_MGMT_ACTION_CMD;
    msg->hdr.length = len;

    std::string plmnId = bngc_enbue_config[BNGC_ENBUE_PLMN_ID_OPTION].GetString();
    memcpy(&attReq.ecgi.plmn_id.octets,
	    bngc_enbue_config[BNGC_ENBUE_PLMN_ID_OPTION].GetString(),
	    strlen (bngc_enbue_config[BNGC_ENBUE_PLMN_ID_OPTION].GetString()));

    Logger::bngc_enbue_app().debug ("PLMN Id: [%s]",attReq.ecgi.plmn_id.octets);

    if(5 == plmnId.size()) 
    {
	attReq.ecgi.plmn_id.num_mnc_digits=2;
    }
    else if(6 == plmnId.size())
    {
	attReq.ecgi.plmn_id.num_mnc_digits=3;
    }
    else
    {
	Logger::bngc_enbue_app().error ("Invalid PLMN ID");
	free (msg);
	return rc; 
    }

    std::string source_eci = bngc_enbue_config[BNGC_ENBUE_SOURCE_ECI_OPTION].GetString();

    memcpy((char *)&attReq.ecgi.eci.bytes,
	    bngc_enbue_config[BNGC_ENBUE_SOURCE_ECI_OPTION].GetString(),
	    strlen (bngc_enbue_config[BNGC_ENBUE_SOURCE_ECI_OPTION].GetString()));

    Logger::bngc_enbue_app().debug ("ECGI ECI : [%s]",attReq.ecgi.eci.bytes );

    std::string kasme = bngc_enbue_config[BNGC_ENBUE_KASME_OPTION].GetString();

    memcpy((char*)&attReq.kasme,
	   bngc_enbue_config[BNGC_ENBUE_KASME_OPTION].GetString(),
	   strlen(bngc_enbue_config[BNGC_ENBUE_KASME_OPTION].GetString()));
    Logger::bngc_enbue_app().debug ("Kasme : [%s]",attReq.kasme);

    std::string xres = bngc_enbue_config[BNGC_ENBUE_XRES_OPTION].GetString();

    memcpy((char *)&attReq.xres, bngc_enbue_config[BNGC_ENBUE_XRES_OPTION].GetString(),
            strlen(bngc_enbue_config[BNGC_ENBUE_XRES_OPTION].GetString()));

    Logger::bngc_enbue_app().debug ("Xres : [%s]",attReq.xres);

    attReq.bitmask = bngc_enbue_config[BNGC_ENBUE_MOBILE_ID_TYPE_OPTION].GetInt();
    attReq.rregparam.follow_on_req = bngc_enbue_config[BNGC_ENBUE_FOLLOWON_REQ_OPTION].GetInt();
    attReq.rregparam.reg_type = bngc_enbue_config[BNGC_ENBUE_REG_TYPE_OPTION].GetInt();

    std::string authkey = bngc_enbue_config[BNGC_ENBUE_AUTH_KEY_OPTION].GetString();

    memcpy((char *)&attReq.rregparam.authkey,
           bngc_enbue_config[BNGC_ENBUE_AUTH_KEY_OPTION].GetString(),
	   strlen(bngc_enbue_config[BNGC_ENBUE_AUTH_KEY_OPTION].GetString()));

    std::string authhop = bngc_enbue_config[BNGC_ENBUE_AUTH_HOP_OPTION].GetString();

    memcpy((char *)&attReq.rregparam.authop,
           bngc_enbue_config[BNGC_ENBUE_AUTH_HOP_OPTION].GetString(),
	   strlen (bngc_enbue_config[BNGC_ENBUE_AUTH_HOP_OPTION].GetString()));

    std::string sqn = bngc_enbue_config[BNGC_ENBUE_SQN_OPTION].GetString();

    memcpy((char *)&attReq.rregparam.sqn,
           bngc_enbue_config[BNGC_ENBUE_SQN_OPTION].GetString(),
	   strlen(bngc_enbue_config[BNGC_ENBUE_SQN_OPTION].GetString()));

    attReq.rregparam.s1_mode = bngc_enbue_config[BNGC_ENBUE_S1MODE_OPTION].GetInt();
    attReq.rregparam.HOattach = bngc_enbue_config[BNGC_ENBUE_HO_OPTION].GetInt();
    attReq.rregparam.LPP = bngc_enbue_config[BNGC_ENBUE_LPP_OPTION].GetInt();
    attReq.rregparam.ue_usg_set = bngc_enbue_config[BNGC_ENBUE_UE_USG_OPTION].GetInt();
    attReq.rregparam.DRX_value = bngc_enbue_config[BNGC_ENBUE_DRX_OPTION].GetInt();
    attReq.rregparam.DCNI = bngc_enbue_config[BNGC_ENBUE_DCNI_OPTION].GetInt();
    attReq.rregparam.intigrityseccap = bngc_enbue_config[BNGC_ENBUE_INTEGITY_OPTION].GetInt();
    attReq.rregparam.NG_RAN_RCU = bngc_enbue_config[BNGC_ENBUE_NGRAN_RCU_OPTION].GetInt();
    	
    strncpy(attReq.rregparam.userName, nai_userid,(SIM_MAX_NAI_USERNAME_LEN-1));
    attReq.rregparam.rid = 0; 
    attReq.bitmask |= IS_SUCI_NAI;

    memcpy (msg->payload, &attReq, sizeof (tEnbSimAttachReq));

    bytesSent = send(bngc_enbue_sock, (char*)msg, len, 0);

    if( bytesSent < 0)
    {
        Logger::bngc_enbue_app().error ("Sending data failed");
    }
    else 
    {
	Logger::bngc_enbue_app().debug ("Attach request sent for ::%s, Bytes Sending:%d",
	        nai_userid, bytesSent);
    }

    free (msg);
    Logger::bngc_enbue_app().debug ("Exiting %s", __func__ );
    return RETURNok; 
}

int bngc_enbue_app::
bngc_enbue_form_detach_request (char *nai_userid)
{
    int            rc = RETURNerror; 
    int            len = 0;
    int            num_bytes = -1;
    char           buffer[MAX_DATA_SIZE];
    tEnbSimFlowUeReq detachUeReq;
    flow_msg_t     *msg = NULL;
 
    len = (sizeof(flow_msg_t) + sizeof(tEnbSimFlowUeReq) - 1);

    msg = (flow_msg_t *) malloc (len);

    if (NULL == msg)
    {
	Logger::bngc_enbue_app().error ("bngc_enbue_form_detach_request: memory allocation failed");
	return rc; 
    }

    Logger::bngc_enbue_app().debug ("Sending 5G DE_REGISTERATION for %s ", nai_userid);
    memset(&detachUeReq,0,sizeof(tEnbSimFlowUeReq));
    memset(msg,0, len); 

    msg->hdr.apiId = enbSimDetachUe; 
    msg->hdr.proc_index = enbSimDetachUe;
    msg->hdr.action = LTE_MGMT_ACTION_CMD;
    msg->hdr.length = len;

    memcpy (detachUeReq.userName, nai_userid, SIM_MAX_NAI_USERNAME_LEN);
    detachUeReq.bitmask |= IS_SUCI_NAI;
    detachUeReq.accesstype               = bngc_enbue_config[BNGC_ENBUE_ACCESS_TYPE_OPTION].GetInt();
    detachUeReq.re_registration_required = bngc_enbue_config[BNGC_ENBUE_REREG_OPTION].GetInt();
    detachUeReq.switchoff                = bngc_enbue_config[BNGC_ENBUE_SWITCHOFF_OPTION].GetInt();
    detachUeReq.identitytype             = bngc_enbue_config[BNGC_ENBUE_IDENTITY_TYPE_OPTION].GetInt();

    if(detachUeReq.identitytype < 0 ||  detachUeReq.identitytype >= 3)
    {
	Logger::bngc_enbue_app().debug("Invalid ID Type");
	detachUeReq.identitytype = 0;
    }

    memcpy (msg->payload, &detachUeReq, sizeof (tEnbSimFlowUeReq));

    if(send(bngc_enbue_sock, (char*)msg, len, 0) < 0)
    {
	Logger::bngc_enbue_app().error ("Sending data failed");
	free (msg);
	return rc;
    }

    Logger::bngc_enbue_app().debug ("UE Idle/Detach Req sent for :%s ",
	    nai_userid);

    Logger::bngc_enbue_app().debug ("Exiting  %s", __func__ );
    free (msg);
    delete_pdu_info (nai_userid);
    return RETURNok; 
}

int bngc_enbue_app::
bngc_enbue_form_pdu_request (char *nai_userid)
{
    int             rc = RETURNerror; 
    int             len = 0;
    int             num_bytes = -1;
    char            buffer[MAX_DATA_SIZE];
    tEnbSimAttachReq attReq;
    flow_msg_t      *msg = NULL;
 
    len = (sizeof(flow_msg_t) + sizeof(tEnbSimAttachReq) - 1);

    msg = (flow_msg_t *) malloc (len);

    if (NULL == msg)
    {
	Logger::bngc_enbue_app().error ("bngc_enbue_form_pdu_request: memory allocation failed");
	return rc; 
    }

    Logger::bngc_enbue_app().debug ("Sending 5G PDU_REQUEST for : %s ",nai_userid);

    memset(&attReq,0, sizeof(tEnbSimAttachReq));
    memset(msg,0, len); 

    msg->hdr.apiId = enbSimPdnConnReq;
    msg->hdr.proc_index= enbSimPdnConnReq;
    msg->hdr.action = LTE_MGMT_ACTION_CMD;
    msg->hdr.length = len;

    strncpy(attReq.rregparam.userName, nai_userid,(SIM_MAX_NAI_USERNAME_LEN-1));
    attReq.rregparam.rid = 0; 
    attReq.rregparam.bitmask |= IS_SUCI_NAI;

    std::string plmnId = bngc_enbue_config[BNGC_ENBUE_PLMN_ID_OPTION].GetString();
    memcpy(&attReq.ecgi.plmn_id.octets,
	    bngc_enbue_config[BNGC_ENBUE_PLMN_ID_OPTION].GetString(),
	    strlen (bngc_enbue_config[BNGC_ENBUE_PLMN_ID_OPTION].GetString()));

    Logger::bngc_enbue_app().debug ("PLMN Id: [%s]",attReq.ecgi.plmn_id.octets);

    if(5 == plmnId.size()) 
    {
	attReq.ecgi.plmn_id.num_mnc_digits=2;
    }
    else if(6 == plmnId.size())
    {
	attReq.ecgi.plmn_id.num_mnc_digits=3;
    }
    else
    {
	Logger::bngc_enbue_app().error ("Invalid PLMN ID");
	free (msg);
	return rc; 
    }

    memcpy(&attReq.ecgi.eci.bytes,
	    bngc_enbue_config[BNGC_ENBUE_SOURCE_ECI_OPTION].GetString(),
	    strlen (bngc_enbue_config[BNGC_ENBUE_SOURCE_ECI_OPTION].GetString()));

    Logger::bngc_enbue_app().debug ("ECGI ECI : [%s]",attReq.ecgi.eci.bytes );

    attReq.rregparam.bitmask |= SET_DNN;

    attReq.apn.apn_length=strlen((char *)bngc_enbue_config[BNGC_ENBUE_APN_OPTION].GetString());

    if(attReq.apn.apn_length>LTE_MAX_APN_LEN)
    {
        Logger::bngc_enbue_app().error ("Invalid APN");
	free (msg);
        return rc; 
    }
    else
    {
        memcpy(&attReq.apn.apn, bngc_enbue_config[BNGC_ENBUE_APN_OPTION].GetString(),attReq.apn.apn_length);
    }

    Logger::bngc_enbue_app().debug ("APN Name : [%s]",attReq.apn.apn);

    attReq.bitmask = bngc_enbue_config[BNGC_ENBUE_SESSIONID_OPTION].GetInt();
    attReq.rregparam.pti = bngc_enbue_config[BNGC_ENBUE_PTI_OPTION].GetInt();
    attReq.rregparam.maxdruplink = bngc_enbue_config[BNGC_ENBUE_MAX_RATE_UL_OPTION].GetInt(); 
    attReq.rregparam.maxdrdownlink = bngc_enbue_config[BNGC_ENBUE_MAX_RATE_DL_OPTION].GetInt(); 

    attReq.rregparam.bitmask |= SET_PDUREQUESTTYPE;
    attReq.rregparam.requesttype = bngc_enbue_config[BNGC_ENBUE_PDU_REQ_TYPE_OPTION].GetInt();

    attReq.rregparam.bitmask |= SET_PDUSESSIONTYPE;
    attReq.rregparam.pdusessiontype = bngc_enbue_config[BNGC_ENBUE_PDU_SESSION_TYPE_OPTION].GetInt();

    memcpy (msg->payload, &attReq, sizeof (tEnbSimAttachReq));

    if(send(bngc_enbue_sock, (char*)msg, len, 0) < 0)
    {
	Logger::bngc_enbue_app().error ("Sending data failed");
	free (msg);
	return rc;
    }

    Logger::bngc_enbue_app().debug ("PDN Req sent for :%s",
	    nai_userid);

    Logger::bngc_enbue_app().debug ("Exiting %s", __func__ );

    free (msg);
    return RETURNok; 
}

int bngc_enbue_app::
bngc_enbue_form_pdu_release (char *nai_userid)
{
    int             rc = RETURNerror; 
    int             len = 0;
    int             num_bytes = -1;
    char            buffer[MAX_DATA_SIZE];
    tEnbSimFlowUeEbiReq delBrReq;
    flow_msg_t      *msg = NULL;
 
    len = (sizeof(flow_msg_t)+sizeof(tEnbSimFlowUeEbiReq)-1);

    msg = (flow_msg_t *) malloc (len);

    if (NULL == msg)
    {
	Logger::bngc_enbue_app().error ("bngc_enbue_form_pdu_release: memory allocation failed");
	return rc; 
    }

    Logger::bngc_enbue_app().debug ("Sending 5G PDU_RELEASE for %s ", nai_userid);

    memset (msg, 0, len);
    memset(&delBrReq,0,sizeof(delBrReq));

    msg->hdr.apiId = enbSimDelPdnReq; 
    msg->hdr.proc_index = enbSimDelPdnReq;
    msg->hdr.action = LTE_MGMT_ACTION_CMD;
    msg->hdr.length = len;

    delBrReq.ebi = bngc_enbue_config[BNGC_ENBUE_PDU_SESSION_OPTION].GetInt();

    Logger::bngc_enbue_app().debug ("EBI  : [%d]",delBrReq.ebi);

    delBrReq.bitmask |= SET_5GSM_CAUSE;

    strncpy(delBrReq.userName, nai_userid,(SIM_MAX_NAI_USERNAME_LEN-1));
    delBrReq.bitmask |= IS_SUCI_NAI;

    memcpy (msg->payload, &delBrReq, sizeof (tEnbSimFlowUeEbiReq));

    if(send(bngc_enbue_sock, (char*)msg, len, 0) < 0)
    {
	Logger::bngc_enbue_app().error ("Sending data failed");
	free (msg);
	return RETURNerror;
    }

    Logger::bngc_enbue_app().debug ("Exiting %s", __func__ );
    free (msg);
    return RETURNok; 
}

void bngc_enbue_app_task(void*)
{
    const task_id_t task_id = TASK_BNGC_ENBUE_APP;

    Logger::bngc_enbue_app().debug("Starting BNGC ENBUE thread loop with task ID %d", TASK_BNGC_ENBUE_APP);

    bngc_enbue_sched_params.sched_priority = BNGC_ENBUE_SCHED_PRIORITY;
    bngc_enbue_sched_params.apply(task_id, Logger::bngc_enbue_app());

    itti_inst->notify_task_ready(task_id);

    do {
        std::shared_ptr<itti_msg> shared_msg = itti_inst->receive_msg(task_id);
        auto *msg = shared_msg.get();
        switch (msg->msg_type)
	{
	    // TODO: Switch cases for message types
	    case ENBUE_REGISTER_REQUEST: 
                if (itti_enbue_register_request* ser =
	                    dynamic_cast<itti_enbue_register_request *>(msg)) {
		    bngc_enbue_app_inst->bngc_enbue_register (std::ref(*ser));
                }
		break;

	    case ENBUE_DEREGISTER_REQUEST: 
                if (itti_enbue_deregister_request* ser =
	                    dynamic_cast<itti_enbue_deregister_request *>(msg)) {
                    bngc_enbue_app_inst->bngc_enbue_deregister (std::ref(*ser));
		}
		break;

	    default:
		Logger::bngc_enbue_app().debug("Received msg with type %d", msg->msg_type);
	}
    } while(true);

}

bngc_enbue_app::bngc_enbue_app()
{
    Logger::bngc_enbue_app().startup("Starting BNG ENBUE control plane app");

    if (itti_inst->create_task(TASK_BNGC_ENBUE_APP, bngc_enbue_app_task, nullptr)) {
        Logger::bngc_app().error( "Cannot create task TASK_BNGC_ENBUE_APP" );
        throw std::runtime_error( "Cannot create task TASK_BNGC_ENBUE_APP" );
    }

    if (itti_inst->create_task(TASK_BNGC_ENBUE_RX_APP, bngc_enbue_rx_app, nullptr)) {
        Logger::bngc_app().error( "Cannot create task TASK_BNGC_ENBUE_RX_APP" );
        throw std::runtime_error( "Cannot create task TASK_BNGC_ENBUE_RX_APP" );
    }


    Logger::bngc_enbue_app().startup("Nailed startup");
}

bngc_enbue_app::~bngc_enbue_app()
{
    Logger::bngc_enbue_app().debug("Deleting BNGC_ENBUE interface");
}

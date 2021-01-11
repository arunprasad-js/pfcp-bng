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
#ifndef FILE_BNGC_ENBUE_CONFIG_HPP_SEEN
#define FILE_BNGC_ENBUE_CONFIG_HPP_SEEN

#include "rapidjson/document.h"

#define BNGC_ENBUE_KASME_OPTION "kasme"
#define BNGC_ENBUE_XRES_OPTION  "xres"
#define BNGC_ENBUE_MOBILE_ID_TYPE_OPTION "mobileidtype"
#define BNGC_ENBUE_FOLLOW_REQ_OPTION "followreq"
#define BNGC_ENBUE_REG_TYPE_OPTION "registrationtype"
#define BNGC_ENBUE_AUTH_KEY_OPTION "authKey"
#define BNGC_ENBUE_AUTH_HOP_OPTION "authOP"
#define BNGC_ENBUE_SESSIONID_OPTION "sessionId"
#define BNGC_ENBUE_PTI_OPTION "PTI"
#define BNGC_ENBUE_MAX_RATE_UL_OPTION "maxDataRateUL"
#define BNGC_ENBUE_MAX_RATE_DL_OPTION "maxDataRateDL"
#define BNGC_ENBUE_RANUE_ID_OPTION "ranUeId"
#define BNGC_ENBUE_AMF_ID_OPTION "amfUeId"
#define BNGC_ENBUE_PROT_PARAM_OPTION "portparam"
#define BNGC_ENBUE_ADDR_TYPE_OPTION "addrtype"
#define BNGC_ENBUE_INST_INDEX_OPTION "enbIndex"
#define BNGC_ENBUE_ECGI_PLMN_ID_OPTION  "plmnoctetsecgi"
#define BNGC_ENBUE_ECGI_CONF_OPTION "confIndxecgi"
#define BNGC_ENBUE_ACCESS_TYPE_OPTION "accesstype"
#define BNGC_ENBUE_ECGI_ECI_ID_OPTION "eci"
#define BNGC_ENBUE_ECGI_TAI_OPTION "taiIndex"
#define BNGC_ENBUE_FOLLOWON_REQ_OPTION "followonreq"
#define BNGC_ENBUE_GROUP_ID_OPTION "groupid"
#define BNGC_ENBUE_IDENTITY_TYPE_OPTION "identitytype"
#define BNGC_ENBUE_IP_ADDR_OPTION "ipaddr"
#define BNGC_ENBUE_HENB_ID_OPTION "henbId"
#define BNGC_ENBUE_PDU_REQ_TYPE_OPTION "pdureqtype"
#define BNGC_ENBUE_PDU_SESSION_OPTION "pduoption"
#define BNGC_ENBUE_PDU_SESSION_STATUS_OPTION "pdustatus"
#define BNGC_ENBUE_PDU_SESSION_TYPE_OPTION "pdutype"
#define BNGC_ENBUE_REREG_OPTION "rereg"
#define BNGC_ENBUE_SCTP_PORT_OPTION "sctpport"
#define BNGC_ENBUE_SWITCHOFF_OPTION "switchoff"
#define BNGC_ENBUE_TAC_OPTION "tac"
#define BNGC_ENBUE_TAI_MME_OPTION "taiConfMmeIndx"
#define BNGC_ENBUE_TAI_NB_LEN_OPTION "nbIdLength"
#define BNGC_ENBUE_TAI_NB_OPTION "nbType"
#define BNGC_ENBUE_TAI_PLMN_ID_OPTION "taiplmnoctets"
#define BNGC_ENBUE_TAI_TAC_OPTION "tac"
#define BNGC_ENBUE_TAI_PLMN_COUNT_OPTION "plmnCount"
#define BNGC_ENBUE_TAC_COUNT_OPTION "counttac"
#define BNGC_ENBUE_UPLINK_STATUS_OPTION "uplinkstatus"
#define BNGC_ENBUE_TAI_INDEX_OPTION "taiIndex"
#define BNGC_ENBUE_FIRST_IMSI_OPTION "firstimsi"
#define BNGC_ENBUE_LAST_IMSI_OPTION "lastimsi"
#define BNGC_ENBUE_PLMN_ID_OPTION "plmnid"
#define BNGC_ENBUE_SOURCE_ECI_OPTION "sourceEci"
#define BNGC_ENBUE_SQN_OPTION "sqn"
#define BNGC_ENBUE_APN_OPTION "apn"
#define BNGC_ENBUE_LINEID_SOURCE_OPTION "lineid"
#define BNGC_ENBUE_IPADDR_OPTION "enb_ipaddr"
#define BNGC_ENBUE_PORT_OPTION "enb_port"
#define BNGC_ENBUE_AMF_INST_OPTION "amfIndex"
#define BNGC_ENBUE_AMF_ADDR_TYPE_OPTION "amfAddrType"
#define BNGC_ENBUE_AMF_SCTP_ADDR_OPTION "amfSctpAddr"
#define BNGC_ENBUE_AMF_SCTP_PORT_OPTION "amfSctpPort"
#define BNGC_ENBUE_S1MODE_OPTION "s1mode"
#define BNGC_ENBUE_HO_OPTION "homode"
#define BNGC_ENBUE_LPP_OPTION "lpp"
#define BNGC_ENBUE_UE_USG_OPTION "ueusg"
#define BNGC_ENBUE_DRX_OPTION "drx"
#define BNGC_ENBUE_DCNI_OPTION "dcni"
#define BNGC_ENBUE_INTEGITY_OPTION "integrity"
#define BNGC_ENBUE_NGRAN_RCU_OPTION "ngranrcu"


#define DEFAULT_BNGC_ENBUE_CONFIG_FILE "bngc_enbue.json"

using namespace rapidjson;

namespace bngc_enbue {
    Document read_bngc_enbue_config_from_file(const char *config_file);
    Document read_bngc_enbue_config_from_file();
}

#endif /* FILE_BNGC_ENBUE_CONFIG_HPP_SEEN */

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
#ifndef FILE_BNGC_ENBUE_APP_HPP_SEEN
#define FILE_BNGC_ENBUE_APP_HPP_SEEN

#include "itti_msg_enbue.hpp" // Reusing itti sxab messages for internal communication
#include <map>

extern Document bngc_enbue_config;

namespace bngc_enbue {

/* Structures and Macros used for communicating with ranbExe/enbUE for 
 * generating 5GC N1/N2 Messages */

#define MAX_EXPEC_MSG           	5
#define MAX_EXPEC_PARAM         	100
#define LTE_MAX_IMSI_BYTES              8
#define LTE_MAX_PLMN_ID_LEN             7
#define LTE_ECI_LEN                     4
#define LTE_MAX_APN_LEN                 100
#define SIM_AUTH_KEY_LENGTH             32
#define SIM_AUTH_OP_LENGTH              32
#define SIM_SQN_LENGTH	                12
#define ENBSIM_MAX_KASME_LEN            32
#define ENBSIM_MAX_XRES_LEN             16
#define MAX_DATA_SIZE                   4096
#define ECGI_CONF_INDEX_MIN             1
#define ECGI_CONF_INDEX_MAX             2000
#define ENODEB_INSTANCE_INDEX_MIN       1
#define ENODEB_INSTANCE_INDEX_MAX       2000
#define ENODEB_INSTANCE_TAI_INDEX_MIN   1
#define ENODEB_INSTANCE_TAI_INDEX_MAX   2000
#define MME_INSTANCE_INDEX_MIN          1
#define MME_INSTANCE_INDEX_MAX          10
#define LTE_IP_ADDRESS_IPV4             1
#define IS_SUCI_NAI                     0x20	

#define endSimStartFlowApi              0
#define enbInstanceConf   		endSimStartFlowApi + 501
#define amfInstanceConf	        	endSimStartFlowApi + 502
#define taiConf			        endSimStartFlowApi + 503
#define ecgiConf		        endSimStartFlowApi + 504
#define dpInstanceConf		        endSimStartFlowApi + 510
#define enbSimAttachReq                 endSimStartFlowApi + 1
#define enbSimDetachUe                  endSimStartFlowApi + 4
#define enbSimPdnConnReq                endSimStartFlowApi + 6
#define enbSimDelPdnReq                 endSimStartFlowApi + 9

#define SET_PDUREQUESTTYPE              0x02
#define SET_PDUSESSIONTYPE              0x04
#define SET_5GSM_CAUSE                  0x08
#define SET_EXT_DIS_PROT_OPT            0x200 
#define SET_DNN                         0x800
#define LTE_IP4_ADDR_LEN                4
#define LTE_IP6_ADDR_LEN                16
#define SIM_MAX_NAI_USERNAME_LEN        150	
#define MAX_NSSAI_ALLOWED               8
#define MAX_TAI_SLICE_COUNT             8

typedef enum {
    ENBSIM_NO_ERROR =0,
    ENBSIM_INVALID_INDEX,
    ENBSIM_INVALID_APID,
    ENBSIM_INVALID_GROUPID,
    ENBSIM_UNABLE_TO_ADD_ENB_INFO,
    ENBSIM_UNABLE_TO_ADD_MME_INFO,
    ENBSIM_UNABLE_TO_ADD_TAI_INFO,
    ENBSIM_UNABLE_TO_ADD_ECGI_INFO,
    ENBSIM_INVALID_TAI_INDEX,
    ENBSIM_INVALID_ECGI_INDEX,
    ENBSIM_ATTACH_REJECT,
    ENBSIM_INVALID_IMSI,
    ENBSIM_UNABLE_TO_ADD_DP_INFO,
    ENBSIM_PROC_TIMER_EXPIRED,
    ENBSIM_NO_CTX_FOUND,
    ENBSIM_INVALID_EBI,
    ENBSIM_S1AP_CAUSE,
    ENBSIM_RAN_NOT_SETUP,
    ENBSIM_AUTH_FAIL,
    ENBSIM_REG_ACCEPT_MAC_ERR,
    ENBSIM_SMC_ERR,
    ENBSIM_DOWNLINK_MAC_ERR
}eEnbSimErrCode;

typedef enum {
    MME_NAS_MSG_REGISTRATION_REQUEST                      = 65,
    MME_NAS_MSG_REGISTRATION_ACCEPT,
    MME_NAS_MSG_REGISTRATION_COMPLETE,
    MME_NAS_MSG_REGISTRATION_REJECT,
    MME_NAS_MSG_DEREGISTER_REQUEST_UE_ORIGINATED,
    MME_NAS_MSG_DEREGISTER_ACCEPT_UE_ORIGINATED,
    MME_NAS_MSG_DEREGISTER_REQUEST_UE_TERMINATED,
    MME_NAS_MSG_DEREGISTER_ACCEPT_UE_TERMINATED,

    MME_NAS_MSG_SERVICE_REQUEST                 = 76,
    MME_NAS_MSG_SERVICE_REJECT,
    MME_NAS_MSG_SERVICE_ACCEPT,

    MME_NAS_CONF_UPDATE_COMMAND                 = 84,
    MME_NAS_CONF_UPDATE_COMPLETE,

    MME_NAS_MSG_AUTH_REQUEST                    = 86,
    MME_NAS_MSG_AUTH_RESPONSE,
    MME_NAS_MSG_AUTH_REJECT,
    MME_NAS_MSG_AUTH_FAILURE,
    MME_NAS_MSG_AUTH_RESULT,

    MME_NAS_MSG_ID_REQUEST                      = 91,
    MME_NAS_MSG_ID_RESPONSE,

    MME_NAS_MSG_SECURITY_MODE_COMMAND           = 93,
    MME_NAS_MSG_SECURITY_MODE_COMPLETE,
    MME_NAS_MSG_SECURITY_MODE_REJECT,

    MME_NAS_5GMM_STATUS                         = 100,
    MME_NAS_MSG_NOTIFICATION,
    MME_NAS_MSG_NOTIFICATION_RESPONSE,

    MME_NAS_MSG_UPLINK_NAS_TRANSPORT            = 103,
    MME_NAS_MSG_DOWNLINK_NAS_TRANSPORT,
    MME_NAS_MSG_UE_CONFIG_UPDATE_COMMAND                     = 84,
    MME_NAS_MSG_UE_CONFIG_UPDATE_COMPLETE                    = 85,
    MME_NAS_MSG_PDU_SESSION_ESTABLISHMENT_REQUEST            = 193,
    MME_NAS_MSG_PDU_SESSION_ESTABLISHMENT_ACCEPT             = 194,
    MME_NAS_MSG_PDU_SESSION_ESTABLISHMENT_REJECT             = 195,

    MME_NAS_MSG_PDU_SESSION_AUTHENTICATION_COMMAND           = 197,
    MME_NAS_MSG_PDU_SESSION_AUTHENTICATION_COMPLETE      = 198 ,
    MME_NAS_MSG_PDU_SESSION_AUTHENTICATION_RESULT            = 199,

    MME_NAS_MSG_PDU_SESSION_MODIFICATION_REQUEST             = 201,
    MME_NAS_MSG_PDU_SESSION_MODIFICATION_REJECT              = 202,
    MME_NAS_MSG_PDU_SESSION_MODIFICATION_COMMAND             = 203,
    MME_NAS_MSG_PDU_SESSION_MODIFICATION_COMPLETE            = 204,
    MME_NAS_MSG_PDU_SESSION_MODIFICATION_COMMAND_REJECT  = 205 ,

    MME_NAS_MSG_PDU_SESSION_RELEASE_REQUEST              = 209,
    MME_NAS_MSG_PDU_SESSION_RELEASE_REJECT                   = 210,
    MME_NAS_MSG_PDU_SESSION_RELEASE_COMMAND              = 211 ,
    MME_NAS_MSG_PDU_SESSION_RELEASE_COMPLETE             = 212,

    MME_NAS_MSG_PDU_SESSION_5GSM_STATUS                      = 214,

}eMmeNasMmMsgType;

typedef enum { 
	SIM_MGMT_ACTION_ADD = 0, 
	SIM_MGMT_ACTION_DEL, 
	SIM_MGMT_ACTION_MODIFY, 
	SIM_MGMT_ACTION_GET,
	SIM_MGMT_ACTION_CMD
} eSimMgmtAction;

/* IMSI Structure */
typedef struct {
    uint8_t  num_bytes;
    /* This shall contain the IMSI in BSD format. */
    uint8_t  octets[LTE_MAX_IMSI_BYTES];
} lte_imsi_t;

typedef struct {
    uint32_t addr;
} lte_ip4_addr_t;

typedef struct {
    uint8_t addr[LTE_IP6_ADDR_LEN];
} lte_ip6_addr_t;

typedef union {
    lte_ip4_addr_t     ip4_addr;
    lte_ip6_addr_t     ip6_addr;
} lte_ip_addr_u_t;

typedef struct {
    uint8_t  ip_addr_type; 
#define LTE_IP_ADDRESS_NONE     0
#define LTE_IP_ADDRESS_IPV4     1
#define LTE_IP_ADDRESS_IPV6     2
#define LTE_IP_ADDRESS_IPV4V6   3
    lte_ip_addr_u_t ip_addr_u;

} lte_ip_address_t;


typedef struct
{
    lte_imsi_t          imsi; /* The IMSI for which this allocation has been 
				 done is indicated in this response. */
    lte_ip_address_t    ueIPAddress[15]; /* Even though both IPv4 and IPv6 is 
						      supported, but at data path, currently
						      only IPv4 address is allocated. */
    lte_ip_address_t    sgwIPAddress; /* Only IPv4 is currently supported */
    lte_ip_address_t    enbIPAddress; /* Only IPv4 is currently supported */
    uint32_t	        enbTeid;
    uint32_t	        sgwTeid;
}tEnbSimAttachResp;


typedef struct sim_ext_header_t
{
    uint32_t  length;
    uint16_t  apiId;
    uint16_t  action;
    uint16_t  proc_index;
    uint16_t  current_scenario;
    uint16_t  localIndexId;
    uint8_t   testcaseName[100];
}sim_ext_header_t;

typedef struct sim_expIe_header_t
{
    uint8_t     ieTag [MAX_EXPEC_MSG][MAX_EXPEC_PARAM];
    uint8_t     msgType [MAX_EXPEC_MSG];
    uint8_t     ieCount [MAX_EXPEC_MSG];
    uint8_t     msgCount;
}sim_expIe_header_t;

typedef struct flow_msg_t
{
    sim_ext_header_t hdr;
    sim_expIe_header_t expecIE;
    unsigned char payload[1];
}flow_msg_t;

typedef struct 
{
    int  result; 
    eEnbSimErrCode errCode;  
}tEnbSimGenResp;

typedef struct {
    uint8_t   length;
    uint8_t   SST[MAX_TAI_SLICE_COUNT];
    uint32_t  SD[MAX_TAI_SLICE_COUNT];
    uint8_t   mappedSST;
    uint32_t  mappedSD;
}tsNSSAI;

//SST and ST Value is supported only
//TODO :- provide support of mappedSST and  mappedSD
typedef struct {
    uint8_t   count;
    uint8_t   SST[MAX_NSSAI_ALLOWED];
    uint32_t  SD[MAX_NSSAI_ALLOWED];
}stNssaiList;


typedef struct {
    unsigned char  num_mnc_digits;
    unsigned char  octets[LTE_MAX_PLMN_ID_LEN];
} enbSim_plmn_id_t;

typedef struct {
    /*
     * First 4 bits are spare
     */
    unsigned char  bytes[LTE_ECI_LEN];
} enbSim_eci_t;

typedef struct {
    enbSim_plmn_id_t   plmn_id;
    enbSim_eci_t       eci;
} enbSim_ecgi_t;

typedef struct {
    unsigned char apn_length;
    unsigned char apn[LTE_MAX_APN_LEN];
}tLteApn;

typedef struct {
    enbSim_plmn_id_t   plmn_id;
    uint8_t    plmnCount;
    uint32_t   tac;
} enbSim_tai_t;

typedef struct
{
    uint16_t         index; 
    lte_ip_address_t sctpIpAddress[2];
    uint16_t         sctpPort;
    uint16_t	     taiIndex;
    uint16_t         groupId; /* More than one eNodeBs which share trust 
				 relation with each other share same group 
			 id. */
    uint8_t          isHenbId[6];
    uint8_t          bitmask;
    uint8_t          sctpAddCount;
}tEnbInstanceConf;


typedef struct
{
    uint16_t         index;
    lte_ip_address_t dpGtpIpAddress; /* Only IPv4 is used in this. */
    uint8_t          phy_inface[255];
    uint16_t         vlan_id;
    lte_ip_address_t dpTeIpAddress;
    lte_ip_address_t dstIpAddress;
    uint16_t         fd;
}tDpInstanceConf;

typedef enum {
    EXT_SUCCESS=0,
    EXT_FAILURE
} eLteResult;

typedef enum { 
    LTE_MGMT_ACTION_ADD = 0, 
    LTE_MGMT_ACTION_DEL, 
    LTE_MGMT_ACTION_MODIFY, 
    LTE_MGMT_ACTION_GET,
    LTE_MGMT_ACTION_CMD,
    LTE_MGMT_ACTION_IND
} eLteMgmtAction;

typedef struct
{
#define IS_SUCI             0x01
#define IS_5G_GUTI          0x02
#define IS_IMEI             0x03
#define IS_REG_INITIAL      0x01
#define IS_REG_MOBILITY     0x02
#define IS_REG_PERIODIC     0x03
#define IS_REG_EMERGENCY    0x04
#define IS_RAN_UE_NGAP_ID   0x20
#define IS_AMF_UE_NGAP_ID   0x40
    unsigned short bitmask;
    unsigned char follow_on_req:1;
    unsigned char reg_type:3;
    unsigned char s1_mode:1;
    unsigned char HOattach:1;
    unsigned char LPP:1;
    unsigned char ue_usg_set:1;   //0: voice, 1:data
    unsigned char DRX_value:4;
    unsigned char DCNI:1;
    unsigned char NSSCI:1;
    unsigned char NG_RAN_RCU:1;
    unsigned char SMS_req:1;
    unsigned char oldPduSessionId;
    unsigned char pti;
    unsigned char maxdruplink;
    unsigned char maxdrdownlink;
    unsigned char requesttype;
    tsNSSAI snssai;
    unsigned char pdusessiontype;
    unsigned char sscmode;
    unsigned char pdusessionreq;
    unsigned short maxpacketfilter;
    enbSim_tai_t tac;
    unsigned short uplinkdatastatus;
    unsigned short pdusessionstatus;
    unsigned char  amfRegionId;
    unsigned short amfSetId:10;
    unsigned char  amfPointer:6;
    unsigned int   _5GTmsi;
    unsigned int   ran_ue_ngap_id;
    unsigned long  long amf_ue_ngap_id;
    unsigned char  authkey[SIM_AUTH_KEY_LENGTH];
    unsigned char  authop[SIM_AUTH_OP_LENGTH];
    unsigned char  sqn[SIM_SQN_LENGTH];
    unsigned char  intigrityseccap;
    unsigned char  cipherseccap;
    unsigned char  protparamkey[SIM_AUTH_KEY_LENGTH];
    unsigned char  protkeyavaialable;
    unsigned char  amfIndx;
    stNssaiList    nssaiList;
    unsigned int   ValidateAllowedNssai;
    unsigned short rid;
    char           userName[SIM_MAX_NAI_USERNAME_LEN];
}ranRegReqParam;

typedef struct
{
#define IS_EMERGENCY_CALL	0x01
#define IS_UECCLESS		0x02
#define IS_CSG_ID_PRESENT	0x04
#define IS_3G_ATTACH		0x08
#define IS_COMBINED_ATTACH	0x10
    lte_imsi_t            imsiStart;
    lte_imsi_t            imsiEnd;
    enbSim_ecgi_t         ecgi;
    tLteApn               apn;
    unsigned char         kasme[ENBSIM_MAX_KASME_LEN];
    unsigned char         xres[ENBSIM_MAX_XRES_LEN];
    unsigned char         cause;
    unsigned char         bitmask;
    ranRegReqParam        rregparam;
}tEnbSimAttachReq;

typedef struct 
{
#define IS_EPS_DETACH                   0x01
#define IS_IMSI_DETACH                  0x02
#define IS_COMBINED_EPS_IMSI_DETACH     0x04
    lte_imsi_t            imsiStart;
    lte_imsi_t            imsiEnd;
    uint8_t               bitmask;
    uint8_t               accesstype:2;
    uint8_t               re_registration_required:1;
    uint8_t               switchoff:1;
    uint8_t               identitytype:3;
    uint16_t              rid;
    char                  userName[SIM_MAX_NAI_USERNAME_LEN];
}tEnbSimFlowUeReq;

typedef struct
{
    uint16_t index;
    enbSim_ecgi_t ecgi;
    uint16_t taiIndex;
}ecgi_conf_t;

typedef struct {
    uint8_t  num_mnc_digits;
    uint8_t  octets[LTE_MAX_PLMN_ID_LEN];
} sim_plmn_id_t;

typedef struct {
    sim_plmn_id_t   plmn_id;
    uint8_t plmnCount;
    uint32_t	tac;
}sim_tai_t;

typedef struct
{
    uint16_t        index;
    sim_tai_t       tai;
    uint16_t        mmeIndex;
    uint16_t        plmnCount;
    uint16_t        tacCount;
    uint16_t        nbType;
    uint16_t        nbIdLength;
}tTaiConf;        

typedef struct
{
    uint16_t         index;
    lte_ip_address_t sctpIpAddress;
    uint16_t         sctpPort;
}tMmeInstanceConf;
	    
typedef struct 
{
    lte_imsi_t            imsiStart;
    lte_imsi_t            imsiEnd;
    uint8_t               ebi;
    uint8_t               bitmask;   
    uint16_t          	  rid;
    char            	  userName[SIM_MAX_NAI_USERNAME_LEN]; 
}tEnbSimFlowUeEbiReq;

typedef struct 
{
    uint32_t           length;
    eLteResult         result; 
    eEnbSimErrCode     errCode;  
    lte_imsi_t         imsi; 
    uint16_t           proc_index;
    uint16_t           current_scenarioId;
    uint16_t           current_localIndexId;
    uint16_t           procId;
    uint16_t           emmCause;
    uint8_t            ieTag;
    uint8_t            msgType;
    uint32_t           responseMsgId;
    lte_ip_address_t   ueIPAddress[15];
    uint32_t           tunnelId[15];
    uint8_t            supiFormat;
    char               userName[SIM_MAX_NAI_USERNAME_LEN];
    uint32_t           qfi;
    uint8_t            payload[1];    
}tEnbSimFlowGenResp;

typedef struct {
    uint16_t src_port, dst_port;
    uint16_t len, checksum;
} t_tcpinfo, t_udpinfo, t_sctpinfo;

typedef struct {
    uint8_t      ip_ver;
    uint16_t     ip_len;
    uint32_t     src_ip, dst_ip;
    uint8_t      proto, tos;
    uint16_t     offset, id;
    uint8_t      first, last, fragment;
} t_ipinfo;

typedef struct {
    uint8_t   flag_fields;
    uint8_t   msg_type;
    uint16_t  length;
    uint32_t  tied;
    uint16_t  seq_no;
    uint8_t   pdu;
    uint8_t   extension_header_type;
    uint8_t   extnHdrLength;
    uint8_t   pdu_spare_type;
    uint8_t   qfi;
    uint8_t   nextextHeader;
}gtp_header_t; 

typedef struct {
    t_ipinfo    ip;
    t_tcpinfo   tcp;
    t_udpinfo   udp;
    t_sctpinfo  sctp;
} t_pktinfo;

typedef struct {
    t_pktinfo pkt_info;
    unsigned char *buffer;
    unsigned int
	total_len,
	l3_offset,
	l4_offset;
    unsigned int verdict_given,transform;
} t_payload;

typedef struct
{
    uint8_t              ver_hdrlen;  /* Version + Header Length */
    uint8_t              tos;         /* Type of service */
    uint16_t             totlen;      /* Total length  IP header + DATA */
    uint16_t             id;          /* Identification */
    uint16_t             fl_offs;     /* Flags + fragment offset */
    uint8_t              ttl;         /* Time to live */
    uint8_t              proto;       /* Protocol */
    uint16_t             cksum;       /* Checksum value */
    uint32_t             src;         /* Source address */
    uint32_t             dest;        /* Destination address */
    uint8_t              options[4];  /* Options field */
} t_ip_header;

#define IP_HDR_LEN      20
#define UDP_HDR_LEN     8
#define IP_VERSION_4    4

#define   IP_VERS_AND_HLEN(version, opt_len) \
          ((version << 4) | (uint8_t)((opt_len + IP_HDR_LEN)>>2))

#define GTPU_PDU        0xFF
#define IP_TCP          6
#define IP_UDP          17
#define IP_SCTP         132
#define GTP_UDP_PORT    2152
#define GTP_HDR_SIZE    16
#define DHCP_SERV_PORT  67

class pdu_establish_connection
{
    public:
	std::string ip_addr;
	std::string circuit_id;
	std::string remote_id;
	std::string ifname;
	std::string iftype;
	std::string session;
	int session_id;
	int ngc_tunnel;
	int qfi;
        char nai_userid[150]; 
	int xid;
        std::vector<std::shared_ptr<pdu_establish_connection>> pdu_connections; // was list
};

class bngc_enbue_app {

public:
    explicit bngc_enbue_app();
    ~bngc_enbue_app();

    int bngc_enbue_sock;
    int gtp_sock;
    int OpenConnection (const char *buf_in_addr, int port);
    int bngc_enbue_ngap_proc ();
    int ecgi_add_conf ();
    int enb_instance_add ();
    int tai_conf_add ();
    int amf_instance_conf ();
    int dp_inst_conf ();
    int bngc_enbue_form_attach_request (char *nai_userid);
    int bngc_enbue_form_detach_request (char *nai_userid);
    int bngc_enbue_form_pdu_request (char *nai_userid);
    int bngc_enbue_form_pdu_release (char *nai_userid);
    int bngc_enbue_register (itti_enbue_register_request &ser);
    int bngc_enbue_deregister (itti_enbue_deregister_request &ser);
    void insert_pdu_connection(std::shared_ptr<pdu_establish_connection>& sp);
    std::vector<std::shared_ptr<pdu_establish_connection>> pdu_connections; // was list
    void update_conn_from_session (int session_id);
    bool find_conn_from_session (int session_id);
    bool find_conn_from_xid (int session_id);
    bool find_conn_from_session_id (std::string session);
    std::shared_ptr<bngc_enbue::pdu_establish_connection> find_conn_from_nai (char *nai);
    void update_pdu_info_from_imsi (char *nai_str, std::string ip_addr, int ngc_tunnel, int qfi);
    std::string get_ctrl_type_from_nai (char *nai_str);
    void print_list ();
    void delete_pdu_info (char *nai_str);
    int get_tunnel_id (int session_id);
    int get_tunnel_id (std::string session_id);
    int get_tunnel_id_from_nai (char *nai_str);
    int get_qfi_id (int session_id);
    int get_qfi_id (std::string session_id);
    int get_qfi_from_nai (char *nai_str);
    int bngc_enbue_packet (itti_enbue_packet &ser);
    int decode_gtp_packet (void *ptr);
    int encode_gtp_packet (char *pkt, int len, uint32_t tied_value, int qfi, uint32_t src_ip, uint32_t dst_ip);
    void gtp_open_recievesocket(uint16_t protocol_type, int *fd, uint32_t ip_address, uint32_t port);
    void construct_ip_header (uint32_t src_ip, uint32_t dst_ip, uint16_t len, unsigned char *message);
    void construct_udp_header (uint16_t src_port, uint16_t dst_port, uint16_t len, unsigned char *message);
    int ip_parse (const unsigned char *s, t_ipinfo *Z);
    int tcp_parse(const unsigned char *s, t_tcpinfo *Z);
    int udp_parse(const unsigned char *s, t_udpinfo *Z);
    int sctp_parse(const unsigned char *s, t_sctpinfo *Z);
    bool is_nai_present (char *nai);
    void get_tunnel_qfi_from_nai (char *nai_str, int *tunnel_id, int *qfi);
};

}
#endif /* FILE_BNGC_ENBUE_APP_HPP_SEEN */

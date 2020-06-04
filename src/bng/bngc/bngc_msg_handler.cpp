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
#include "bngc_msg_handler.hpp"
#include "bngc_pfcp_association.hpp"
#include "3gpp_29.244.h" // PFCP protocol
#include "common_defs.h" // Return status
#include "itti.hpp" // itti_mw
#include "pfcp.hpp" // Default port
#include "uint_generator.hpp" // Generating TXIDs

#include <arpa/inet.h> // IP data structures
#include <functional> // Hash

using namespace bngc;
using namespace rapidjson;

extern bngc_app *bngc_app_inst;
extern itti_mw *itti_inst;
extern Document bngc_config;

bool bngc::validate_pppd_json_msg(Document &d)
{
    // TODO: Refactor this according to the fields required for each event type
    // TODO: Be more verbose about the problem
    return !d.HasParseError() && d.HasMember(PPPD_EVENT)
            && d.HasMember(PPPD_IP_ADDR)
            && d.HasMember(PPPD_CTRL_IFNAME)
            && d.HasMember(PPPD_CALLED_SESSION_ID)
            && d.HasMember(PPPD_CALLING_SESSION_ID)
            && d.HasMember(PPPD_PPPOE_SESSIONID);
}

// Creates a 64 bit session ID based on the hash value of nas ID and PPPoE session ID
seid_t bngc::generate_session_id(std::string nas_id, int pppoe_session_id)
{
    std::size_t nas_hash = std::hash<std::string>{}(nas_id);

    seid_t seid = (nas_hash << 32) & 0xFFFFFFFF00000000;
    seid = seid | (pppoe_session_id & 0xFFFFFFFF);

    Logger::bngc_app().debug("Generated session id " SEID_FMT " with hash of NAS ID %s " SEID_FMT " and PPPoE session id: %d",
            seid, nas_id.c_str(), nas_hash, pppoe_session_id);

    return seid;
}

int bngc::generate_upstream_pdr_ie(pfcp::create_pdr *create_pdr,
        std::string called_station_id, pfcp::far_id_t far_id)
{
    unsigned int bytes[6]; // Used to read mac addresses from strings
    int i;

    // Mandatory IEs, according to CUPS implementation
    pfcp::pdr_id_t pdr_id = {};
    pfcp::precedence_t precedence = {};
    pfcp::pdi pdi = {};
    pfcp::source_interface_t source_interface = {};

    // Generate PDR ID
    pdr_id.rule_id = util::uint_uid_generator<uint16_t>::get_instance().get_uid();
    // Set precedence to 0. No other precedence values are considered at the moment
    precedence.precedence = 0;

    // Source interface set to ACCESS (ACCESS is for uplink, CORE for downlink)
    source_interface.interface_value = pfcp::INTERFACE_VALUE_ACCESS;

    // Ethernet packet filter to set source MAC address
    pfcp::ethernet_packet_filter epf = {};

    // EPF MAC address from called station id
    pfcp::mac_address_t epf_mac_address = {};
    epf_mac_address.sour = 1;

    if (std::sscanf(called_station_id.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x",
            &bytes[0], &bytes[1], &bytes[2], &bytes[3], &bytes[4], &bytes[5]) != 6)
    {
        Logger::bngc_app().error("Invalid called id mac address: %s",
                called_station_id.c_str());
    }

    for(i=0;i<6;i++) {
        epf_mac_address.source_mac_address[i] = (uint8_t)bytes[i];
    }

    epf.set(epf_mac_address);

    pdi.set(source_interface);
    pdi.set(epf);

    create_pdr->set(pdr_id);
    create_pdr->set(precedence);
    create_pdr->set(pdi);
    create_pdr->set(far_id);

    return RETURNok;
}

int bngc::generate_downstream_pdr_ie(pfcp::create_pdr *create_pdr,
        std::string ip_addr, std::string calling_station_id,
        pfcp::far_id_t far_id)
{
    unsigned char ue_in_addr_chr[sizeof (struct in_addr)+1]; // For translating ip addr e to binary format

    unsigned int bytes[6]; // Used to read mac addresses from strings
    int i;

    // Mandatory IEs, according to CUPS implementation
    pfcp::pdr_id_t pdr_id = {};
    pfcp::precedence_t precedence = {};
    pfcp::pdi pdi = {};
    pfcp::source_interface_t source_interface = {};

    // BBF Outer header removal
    pfcp::bbf_outer_header_removal_t bbf_ohr = {};
    bbf_ohr.bbf_outer_header_removal_description = BBF_OUTER_HEADER_REMOVAL_PPP_PPPOE_ETHERNET;

    // Generate PDR ID
    pdr_id.rule_id = util::uint_uid_generator<uint16_t>::get_instance().get_uid();
    // Set precedence to 0. No other precedence values are considered at the moment
    precedence.precedence = 0;

    // Source interface set to CORE (ACCESS is for uplink, CORE for downlink)
    source_interface.interface_value = pfcp::INTERFACE_VALUE_CORE;

    // IP address
    pfcp::ue_ip_address_t ue_ip_address = {};
    ue_ip_address.v4 = 1;

    // Convert UEIP string to binary format
    if (inet_pton (AF_INET, ip_addr.c_str(), ue_in_addr_chr) != 1) {
        Logger::bngc_app().error("Invalid BNGU IPV4 address: %s", ip_addr.c_str());
        return RETURNerror;
    }
    memcpy (&ue_ip_address.ipv4_address, ue_in_addr_chr, sizeof (struct in_addr));

    // Ethernet packet filter to set mac address
    pfcp::ethernet_packet_filter epf = {};

    // EPF MAC address from calling station id
    pfcp::mac_address_t epf_mac_address = {};
    epf_mac_address.dest = 1;

    if (std::sscanf(calling_station_id.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x",
            &bytes[0], &bytes[1], &bytes[2], &bytes[3], &bytes[4], &bytes[5]) != 6)
    {
        Logger::bngc_app().error("Invalid calling id mac address: %s",
                calling_station_id.c_str());
    }

    for(i=0;i<6;i++) {
        epf_mac_address.destination_mac_address[i] = (uint8_t)bytes[i];
    }

    epf.set(epf_mac_address);

    pdi.set(source_interface);
    pdi.set(ue_ip_address);
    pdi.set(epf);

    create_pdr->set(pdr_id);
    create_pdr->set(precedence);
    create_pdr->set(pdi);
    create_pdr->set(far_id);
    create_pdr->set(bbf_ohr);

    return RETURNok;
}

int bngc::generate_upstream_far_ie(pfcp::create_far *create_far,
        pfcp::far_id_t *far_id)
{
    pfcp::apply_action_t apply_action = {};
    pfcp::forwarding_parameters forwarding_parameters = {};

    apply_action.forw = 1;

    far_id->far_id = util::uint_uid_generator<uint32_t>::get_instance().get_uid();

    pfcp::destination_interface_t destination_interface = {};
    destination_interface.interface_value = pfcp::INTERFACE_VALUE_CORE;

    forwarding_parameters.set(destination_interface);

    create_far->set(apply_action);
    create_far->set(*far_id);
    create_far->set(forwarding_parameters);

    return RETURNok;
}

int bngc::generate_downstream_far_ie(pfcp::create_far *create_far,
        pfcp::far_id_t *far_id, uint8_t endpoint_id)
{
     // Create FAR with FAR ID, Linked Traffic Endpoint ID, and BBF Outer Header Creation
    pfcp::apply_action_t apply_action = {};
    pfcp::forwarding_parameters forwarding_parameters = {};

    apply_action.forw = 1;

    pfcp::bbf_outer_header_creation_t bbf_outer_header_creation = {};
    bbf_outer_header_creation.bbf_outer_header_creation_description = pfcp::BBF_OUTER_HEADER_CREATION_TRAFFIC_ENDPOINT;

    far_id->far_id = util::uint_uid_generator<uint32_t>::get_instance().get_uid();

    pfcp::traffic_endpoint_id_t traffic_endpoint_id = {};
    traffic_endpoint_id.traffic_endpoint_id = endpoint_id;

    pfcp::destination_interface_t destination_interface = {};
    destination_interface.interface_value = pfcp::INTERFACE_VALUE_ACCESS;

    forwarding_parameters.set(bbf_outer_header_creation);
    forwarding_parameters.set(traffic_endpoint_id);
    forwarding_parameters.set(destination_interface);

    create_far->set(apply_action);
    create_far->set(*far_id);
    create_far->set(forwarding_parameters);

    return RETURNok;
}

bool bngc::get_vlan_tags_from_ctrl_ifname(std::string ctrl_ifname, pfcp::s_tag_t *s_tag,
        pfcp::c_tag_t *c_tag)
{
    std::string s_tag_str, c_tag_str;

    std::size_t dot1 = ctrl_ifname.find('.');

    if (dot1 != std::string::npos) {
        std::size_t dot2 = ctrl_ifname.find('.', dot1+1);

        if (dot2 == std::string::npos) {
            Logger::bngc_app().error("Invalid ctrl iface name: %s", ctrl_ifname.c_str());
            return false;
        }

        s_tag_str = ctrl_ifname.substr(dot1+1, dot2-dot1-1);
        c_tag_str = ctrl_ifname.substr(dot2+1);

        s_tag->vid = 1;
        s_tag->svid_value = static_cast<uint16_t>(std::stoi(s_tag_str));

        c_tag->vid = 1;
        c_tag->cvid_value = static_cast<uint16_t>(std::stoi(c_tag_str));

        Logger::bngc_app().debug("s_tag: %d", s_tag->svid_value);
        Logger::bngc_app().debug("c_tag: %d", c_tag->cvid_value);
    }
    else {
        Logger::bngc_app().error("Invalid ctrl iface name: %s", ctrl_ifname.c_str());
        return false;
    }
    return true;
}

int bngc::generate_create_traffic_endpoint_ie(
        pfcp::create_traffic_endpoint *create_traffic_endpoint,
        uint8_t endpoint_id, std::string called_station_id,
        std::string ctrl_ifname, int pppoe_session_id_int)
{
    unsigned int bytes[6]; // Used to read mac addresses from strings
    int i;

    pfcp::traffic_endpoint_id_t traffic_endpoint_id = {};
    traffic_endpoint_id.traffic_endpoint_id = endpoint_id;

    // Traffic endpoint MAC address from called_station_id
    pfcp::mac_address_t te_mac_address = {};
    te_mac_address.dest = 1;

    if (std::sscanf(called_station_id.c_str(), "%02x:%02x:%02x:%02x:%02x:%02x",
            &bytes[0], &bytes[1], &bytes[2], &bytes[3], &bytes[4], &bytes[5]) != 6)
    {
        Logger::bngc_app().error("Invalid calling id mac address: %s",
                called_station_id.c_str());
    }

    for(i=0;i<6;i++) {
        te_mac_address.destination_mac_address[i] = (uint8_t)bytes[i];
    }

    // S-Tag + C-Tag from ctrl iface name
    pfcp::s_tag_t s_tag = {};
    pfcp::c_tag_t c_tag = {};

    if(!get_vlan_tags_from_ctrl_ifname(ctrl_ifname, &s_tag, &c_tag)) {
        Logger::bngc_app().error("Error getting S-TAG and C-TAG values");
        return RETURNerror;
    }

    // PPPoE Session ID
    pfcp::pppoe_session_id_t pppoe_session_id = {};
    pppoe_session_id.pppoe_session_id = (uint16_t)pppoe_session_id_int;

    create_traffic_endpoint->set(s_tag);
    create_traffic_endpoint->set(c_tag);
    create_traffic_endpoint->set(pppoe_session_id);
    create_traffic_endpoint->set(te_mac_address);
    create_traffic_endpoint->set(traffic_endpoint_id);

    return RETURNok;
}


int bngc::translate_ppp_to_pfcp_session_establishment(Document &d,
    itti_sxab_session_establishment_request *itti_sereq)
{
    std::string bngc_ip = bngc_config[BNGC_IPV4_ADDRESS_OPTION].GetString();
    unsigned char bngc_in_addr_chr[sizeof (struct in_addr)+1]; // For bngc IP in binary format

    int rc;
    seid_t seid;

    std::string ip_addr = d[PPPD_IP_ADDR].GetString();
    std::string ctrl_ifname = d[PPPD_CTRL_IFNAME].GetString();
    std::string called_station_id = d[PPPD_CALLED_SESSION_ID].GetString();
    std::string calling_station_id = d[PPPD_CALLING_SESSION_ID].GetString();
    int pppoe_session_id_int = d[PPPD_PPPOE_SESSIONID].GetInt();

    std::string nas_id;

    Logger::bngc_app().debug("IP Address: %s", ip_addr.c_str());
    Logger::bngc_app().debug("ctrl_ifname: %s", ctrl_ifname.c_str());
    Logger::bngc_app().debug("called_station_id %s", called_station_id.c_str());
    Logger::bngc_app().debug("calling_station_id: %s", calling_station_id.c_str());
    Logger::bngc_app().debug("pppoe_sessionid: %d", pppoe_session_id_int);

    if(d.HasMember(PPPD_NAS_ID)) {
        nas_id = d[PPPD_NAS_ID].GetString();
        Logger::bngc_app().debug("NAS ID: %s", nas_id.c_str());
        auto bngu_endpoint = bngc_app_inst->bngu_endpoints.find(nas_id);
        if (bngu_endpoint == bngc_app_inst->bngu_endpoints.end()) {
            Logger::bngc_app().warn("No bngu endpoint found for NAS ID %s. Stopping request handler",
                    nas_id.c_str());
            return RETURNerror;
        }
        itti_sereq->r_endpoint = bngu_endpoint->second;
    } else {
        nas_id = std::string(DEFAULT_NAS_ID);
        Logger::bngc_app().debug("No NAS ID specified. Using default NAS ID: %s", nas_id.c_str());
        auto bngu_endpoint = bngc_app_inst->bngu_endpoints.find(nas_id);
        itti_sereq->r_endpoint = bngu_endpoint->second;
    }

    // Check if there's an association with bngu endpoint
    pfcp::node_id_t bngu_node_id_ie = {};
    bngu_node_id_ie.node_id_type = pfcp::NODE_ID_TYPE_IPV4_ADDRESS;

    struct sockaddr_in * addr_in = (struct sockaddr_in *)&itti_sereq->r_endpoint.addr_storage;
    struct in_addr endpoint_ip = addr_in->sin_addr;

    memcpy (&bngu_node_id_ie.u1.ipv4_address, &endpoint_ip, sizeof (struct in_addr));
    std::shared_ptr<pfcp_association> sa = std::shared_ptr<pfcp_association>(nullptr);

    // If there isn't, stop processing request
    if (!pfcp_associations::get_instance().get_association(bngu_node_id_ie, sa)) {
        Logger::bngc_app().warn("No association found with BNGU endpoint %s. Stopping request handler.",
                itti_sereq->r_endpoint.toString().c_str());
        return RETURNerror;
    }

    seid = generate_session_id(nas_id, pppoe_session_id_int);

    // Internal ITTI message fields
    itti_sereq->seid = seid;
    itti_sereq->trxn_id = util::uint_uid_generator<uint64_t>::get_instance().get_uid(); // Transaction ID

    // --------------------------------------------------------------------------
    // POPULATING IES

    // Convert BNGC IP string to binary format
    if (inet_pton (AF_INET, bngc_ip.c_str(), bngc_in_addr_chr) != 1) {
        Logger::bngc_app().error("Invalid BNGC IPV4 address: %s", bngc_ip);
        return RETURNerror;
    }

    // Node id set from BNGC IP (source)
    pfcp::node_id_t node_id_ie = {};
    node_id_ie.node_id_type = pfcp::NODE_ID_TYPE_IPV4_ADDRESS;
    // Populate node id with BNGC ip address
    memcpy (&node_id_ie.u1.ipv4_address, bngc_in_addr_chr, sizeof (struct in_addr));
    itti_sereq->pfcp_ies.set(node_id_ie);

    // F-SEID (Fully Qualified SEID) set to BNGC address + session ID
    pfcp::fseid_t cp_fseid_ie = {};
    cp_fseid_ie.v4 = 1;
    memcpy (&cp_fseid_ie.ipv4_address, bngc_in_addr_chr, sizeof (struct in_addr));
    cp_fseid_ie.seid = seid;
    itti_sereq->pfcp_ies.set(cp_fseid_ie);

    uint8_t traffic_endpoint_id = DEFAULT_TRAFFIC_ENDPOINT_ID;

    // FARs (Actions)
    pfcp::create_far upstream_far = {};
    pfcp::far_id_t upstream_far_id = {};
    pfcp::create_far downstream_far = {};
    pfcp::far_id_t downstream_far_id = {};

    rc = generate_upstream_far_ie(&upstream_far, &upstream_far_id);

    if(rc != RETURNok) {
        Logger::bngc_app().error("Error creating upstream FAR IE");
        return RETURNerror;
    }

    rc = generate_downstream_far_ie(&downstream_far, &downstream_far_id,
            traffic_endpoint_id);

    if(rc != RETURNok) {
        Logger::bngc_app().error("Error creating downstream FAR IE");
        return RETURNerror;
    }

    // PDRs (Matches)
    pfcp::create_pdr create_upstream_pdr = {};
    pfcp::create_pdr create_downstream_pdr = {};

    rc = generate_upstream_pdr_ie(&create_upstream_pdr, called_station_id,
            upstream_far_id);

    if(rc != RETURNok) {
        Logger::bngc_app().error("Error creating upstream PDR IE");
        return RETURNerror;
    }

    rc = generate_downstream_pdr_ie(&create_downstream_pdr, ip_addr,
            calling_station_id, downstream_far_id);

    if(rc != RETURNok) {
        Logger::bngc_app().error("Error creating upstream PDR IE");
        return RETURNerror;
    }

    // Create traffic endpoint (auxiliary fields)
    pfcp::create_traffic_endpoint create_traffic_endpoint = {};
    rc = generate_create_traffic_endpoint_ie(&create_traffic_endpoint,
            traffic_endpoint_id, called_station_id, ctrl_ifname, pppoe_session_id_int);

    if(rc != RETURNok) {
        Logger::bngc_app().error("Error creating traffic endpoint");
        return RETURNerror;
    }

    itti_sereq->pfcp_ies.set(create_upstream_pdr);
    itti_sereq->pfcp_ies.set(create_downstream_pdr);
    itti_sereq->pfcp_ies.set(upstream_far);
    itti_sereq->pfcp_ies.set(downstream_far);
    itti_sereq->pfcp_ies.set(create_traffic_endpoint);

    return RETURNok;
}

int bngc::translate_ppp_to_pfcp_session_deletion(Document &d,
    itti_sxab_session_deletion_request *itti_sdreq)
{
    int rc;

    std::string nas_id;
    seid_t seid;

    int pppoe_session_id_int = d[PPPD_PPPOE_SESSIONID].GetInt();

    Logger::bngc_app().debug("pppoe_sessionid: %d", pppoe_session_id_int);

    if(d.HasMember(PPPD_NAS_ID)) {
        nas_id = d[PPPD_NAS_ID].GetString();
        Logger::bngc_app().debug("NAS ID: %s", nas_id.c_str());
        auto bngu_endpoint = bngc_app_inst->bngu_endpoints.find(nas_id);
        if (bngu_endpoint == bngc_app_inst->bngu_endpoints.end()) {
            Logger::bngc_app().warn("No bngu endpoint found for NAS ID %s. Stopping request handler",
                    nas_id.c_str());
            return RETURNerror;
        }
        itti_sdreq->r_endpoint = bngu_endpoint->second;
    } else {
        nas_id = std::string(DEFAULT_NAS_ID);
        Logger::bngc_app().debug("No NAS ID specified. Using default NAS ID: %s", nas_id.c_str());
        auto bngu_endpoint = bngc_app_inst->bngu_endpoints.find(nas_id);
        itti_sdreq->r_endpoint = bngu_endpoint->second;
    }

    // Check if there's an association with bngu endpoint
    pfcp::node_id_t bngu_node_id_ie = {};
    bngu_node_id_ie.node_id_type = pfcp::NODE_ID_TYPE_IPV4_ADDRESS;

    struct sockaddr_in * addr_in = (struct sockaddr_in *)&itti_sdreq->r_endpoint.addr_storage;
    struct in_addr endpoint_ip = addr_in->sin_addr;

    memcpy (&bngu_node_id_ie.u1.ipv4_address, &endpoint_ip, sizeof (struct in_addr));
    std::shared_ptr<pfcp_association> sa = std::shared_ptr<pfcp_association>(nullptr);

    // If there isn't, stop processing request
    if (!pfcp_associations::get_instance().get_association(bngu_node_id_ie, sa)) {
        Logger::bngc_app().warn("No association found with BNGU endpoint %s. Stopping request handler.",
                itti_sdreq->r_endpoint.toString().c_str());
        return RETURNerror;
    }

    seid = generate_session_id(nas_id, pppoe_session_id_int);

    // Internal ITTI message fields
    itti_sdreq->seid = seid;
    itti_sdreq->trxn_id = util::uint_uid_generator<uint64_t>::get_instance().get_uid(); // Transaction ID

    return RETURNok;
}

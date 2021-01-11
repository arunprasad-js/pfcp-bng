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
#include "3gpp_29.244.h" // PFCP protocol fields
#include "bngu_msg_handler.hpp"

#define MAX_DPDK_CLI_MSG_SIZE 250

using namespace bngu;

// Validates pfcp session establishment request message and sets response accordingly
bool bngu::process_session_establishment_request(
        pfcp::pfcp_session_establishment_request &request,
        pfcp::pfcp_session_establishment_response &response,
        const char *bngu_ip)
{
    unsigned char bngu_in_addr_chr[sizeof (struct in_addr)+1]; // For bngu IP in binary format
    char ue_ip_addr_str[INET_ADDRSTRLEN];
    pfcp::mac_address_t subscriber_mac_address;
    int pppoe_session_id;
    pfcp::s_tag_t s_tag = {};
    pfcp::c_tag_t c_tag = {};
    pfcp::fteid_t local_fteid; 

    bool read_ue_ip_addr = false;
    bool read_epf_mac_address = false;
    bool read_linked_traffic_endpoint_id = false;

    // Populate PFCP response fields
    // Set request CAUSE as ACCEPTED by default
    pfcp::cause_t cause_ie = {.cause_value = pfcp::CAUSE_VALUE_REQUEST_ACCEPTED};
    pfcp::offending_ie_t offending_ie = {};

    // Set node id from BNGU IP (source)
    pfcp::node_id_t node_id_ie = {};
    node_id_ie.node_id_type = pfcp::NODE_ID_TYPE_IPV4_ADDRESS;
    if (inet_pton (AF_INET, bngu_ip, bngu_in_addr_chr) != 1) { // Convert IP string to binary
        Logger::bngu_app().error("Invalid BNGU IPV4 address: %s", bngu_ip);
        return false;
    }
    memcpy (&node_id_ie.u1.ipv4_address, bngu_in_addr_chr, sizeof (struct in_addr));
    response.set(node_id_ie);

    // TODO: Differentiate between uplink and downlink PDR/FAR when getting values from session request
    // At the moment, the PDRs are all filled the same way, so we know where to get the value to use in DPDK.
    // This processing phase can have more intelligence to differenciate the PDR/FARs.
    for (auto it : request.create_pdrs) {
        pfcp::create_pdr& pdr = it;
        pfcp::pdr_id_t pdr_id = {};
        pfcp::pdi pdi = {};
        pfcp::far_id_t far_id = {};
        pfcp::create_far cr_far = {};

        if (not pdr.get(pdr_id)) {
            Logger::bngu_app().error("Missing PDR ID");
            cause_ie.cause_value = pfcp::CAUSE_VALUE_MANDATORY_IE_MISSING;
            offending_ie.offending_ie = PFCP_IE_PACKET_DETECTION_RULE_ID;
            response.set(cause_ie);
            response.set(offending_ie);
            return false;
        }

        Logger::bngu_app().debug("Processing PDR %d", pdr_id.rule_id);

        if (not pdr.pdi.first) {
            Logger::bngu_app().error("Missing PDI");
            cause_ie.cause_value = pfcp::CAUSE_VALUE_MANDATORY_IE_MISSING;
            offending_ie.offending_ie = PFCP_IE_PDI;
            response.set(cause_ie);
            response.set(offending_ie);
            return false;
        }

        if (not pdr.get(far_id)) {
            Logger::bngu_app().error("Missing FAR ID");
            cause_ie.cause_value = pfcp::CAUSE_VALUE_MANDATORY_IE_MISSING;
            offending_ie.offending_ie = PFCP_IE_FAR_ID;
            response.set(cause_ie);
            response.set(offending_ie);
            return false;
        }


        if (not request.get(far_id, cr_far)) {
            Logger::bngu_app().error("Missing Create FAR");
            cause_ie.cause_value = pfcp::CAUSE_VALUE_MANDATORY_IE_MISSING;
            offending_ie.offending_ie = PFCP_IE_CREATE_FAR;
            response.set(cause_ie);
            response.set(offending_ie);
            return false;
        }

        pdi = pdr.pdi.second;

        if (not pdi.source_interface.first) {
            Logger::bngu_app().error("Missing source interface");
            cause_ie.cause_value = pfcp::CAUSE_VALUE_MANDATORY_IE_MISSING;
            offending_ie.offending_ie = PFCP_IE_SOURCE_INTERFACE;
            response.set(cause_ie);
            response.set(offending_ie);
            return false;
        }

        if (pdi.ue_ip_address.first) {
            if (pdi.ue_ip_address.second.v4) {
                inet_ntop(AF_INET, &pdi.ue_ip_address.second.ipv4_address,
                        ue_ip_addr_str, sizeof(ue_ip_addr_str));

                Logger::bngu_app().debug("UE IP address: %s", ue_ip_addr_str);
                read_ue_ip_addr = true;
            }
            else {
                Logger::bngu_app().error("Invalid IPv4 UE address in request");
                cause_ie.cause_value = pfcp::CAUSE_VALUE_REQUEST_REJECTED;
                response.set(cause_ie);
                return false;
            }
        }

        if (pdi.ethernet_packet_filter.first
                && pdi.ethernet_packet_filter.second.mac_address.first) {
            pfcp::mac_address_t epf_mac_address = pdi.ethernet_packet_filter.second.mac_address.second;
            subscriber_mac_address = pdi.ethernet_packet_filter.second.mac_address.second;
            if (epf_mac_address.dest) {
                Logger::bngu_app().debug("EPF dest MAC address:  %02X:%02X:%02X:%02X:%02X:%02X",
                        epf_mac_address.destination_mac_address[0],
                        epf_mac_address.destination_mac_address[1],
                        epf_mac_address.destination_mac_address[2],
                        epf_mac_address.destination_mac_address[3],
                        epf_mac_address.destination_mac_address[4],
                        epf_mac_address.destination_mac_address[5]);
                read_epf_mac_address = true;
            }
        }

        if (pdi.qfi.first) {
            if (pdi.qfi.second.qfi) {
                Logger::bngu_app().debug("GTPu Extension Header QFI Value: %d", pdi.qfi.second.qfi);
            }
            else {
                Logger::bngu_app().error("Invalid QFI in request");
                cause_ie.cause_value = pfcp::CAUSE_VALUE_REQUEST_REJECTED;
                response.set(cause_ie);
                return false;
            }
        }

        // Marking PDR as created in response message;
        pfcp::created_pdr created_pdr = {};
        created_pdr.set(pdr.pdr_id.second);
        response.set(created_pdr);
    }

    // Stop processing if we cannot read UE IP Address from PDRs
    if(!read_ue_ip_addr) {
        Logger::bngu_app().error("Couldn't read UE IP address in PDRs");
        response.set(cause_ie);
        if(cause_ie == pfcp::CAUSE_VALUE_MANDATORY_IE_MISSING) {
            response.set(offending_ie);
        }
        return false;
    }

    // Stop processing if we didn't read EPF MAC address from PDRs
    if(!read_epf_mac_address) {
        Logger::bngu_app().error("Couldn't read EPF destination MAC address in PDRs");
        cause_ie.cause_value = pfcp::CAUSE_VALUE_MANDATORY_IE_MISSING;
        offending_ie.offending_ie = PFCP_IE_MAC_ADDRESS;
        response.set(cause_ie);
        response.set(offending_ie);
        return false;
    }

    // Look for FAR with linked create traffic endpoint ID
    pfcp::traffic_endpoint_id_t linked_traffic_endpoint_id = {};

    for (auto it : request.create_fars) {
        pfcp::create_far& far = it;

        // Get forwarding parameters
        if (far.forwarding_parameters.first) {
            pfcp::forwarding_parameters fp = far.forwarding_parameters.second;

            // Traffic endpoint ID to match with create traffic endpoint it
            if (fp.linked_traffic_endpoint_id.first) {
                linked_traffic_endpoint_id = fp.linked_traffic_endpoint_id.second;
                Logger::bngu_app().debug("Linked traffic endpoint id: %d", linked_traffic_endpoint_id);
                read_linked_traffic_endpoint_id = true;
            }
        }
    }

    if(!read_linked_traffic_endpoint_id) {
        Logger::bngu_app().error("No linked traffic endpoint id in FARs");
        cause_ie.cause_value = pfcp::CAUSE_VALUE_MANDATORY_IE_MISSING;
        offending_ie.offending_ie = PFCP_IE_TRAFFIC_ENDPOINT_ID;
        response.set(cause_ie);
        response.set(offending_ie);
        return false;
    }

    // Create endpoint id
    if (request.create_traffic_endpoint.first) {
        pfcp::create_traffic_endpoint cte = request.create_traffic_endpoint.second;

        if (cte.traffic_endpoint_id.first) {
            pfcp::traffic_endpoint_id_t cte_traffic_endpoint_id = cte.traffic_endpoint_id.second;
            Logger::bngu_app().debug("CTE traffic endpoint ID: %d", cte_traffic_endpoint_id);

            if(cte_traffic_endpoint_id.traffic_endpoint_id != linked_traffic_endpoint_id.traffic_endpoint_id) {
                Logger::bngu_app().error("Mismatch between FAR Linked Traffic Endpoint ID and Create Traffic Endpoint ID");
                cause_ie.cause_value = pfcp::CAUSE_VALUE_REQUEST_REJECTED;
                response.set(cause_ie);
                return false;
            }

        } else {
            Logger::bngu_app().error("No traffic endpoint id in create traffic endpoint");
            cause_ie.cause_value = pfcp::CAUSE_VALUE_MANDATORY_IE_MISSING;
            offending_ie.offending_ie = PFCP_IE_TRAFFIC_ENDPOINT_ID;
            response.set(cause_ie);
            response.set(offending_ie);
            return false;
        }

        if (cte.local_fteid.first && cte.local_fteid.second.teid) {
            local_fteid = cte.local_fteid.second;
            inet_ntop(AF_INET, &local_fteid.ipv4_address,
		      ue_ip_addr_str, sizeof(ue_ip_addr_str));
            Logger::bngu_app().debug("UE IP Address: %s,  F-TEID Tunnel Id: 0x%X",
                    ue_ip_addr_str, local_fteid.teid);
        } else {
            Logger::bngu_app().error("Missing create traffic endpoint Tunnel ID");
            cause_ie.cause_value = pfcp::CAUSE_VALUE_MANDATORY_IE_MISSING;
            offending_ie.offending_ie = PFCP_IE_F_TEID;
            response.set(cause_ie);
            response.set(offending_ie);
            return false;
        }

        if (cte.mac_address.first && cte.mac_address.second.dest) {
            pfcp::mac_address_t cte_mac_address = cte.mac_address.second;
            Logger::bngu_app().debug("CTE destination MAC address: %02X:%02X:%02X:%02X:%02X:%02X",
                    cte_mac_address.destination_mac_address[0],
                    cte_mac_address.destination_mac_address[1],
                    cte_mac_address.destination_mac_address[2],
                    cte_mac_address.destination_mac_address[3],
                    cte_mac_address.destination_mac_address[4],
                    cte_mac_address.destination_mac_address[5]);
        } else {
            Logger::bngu_app().error("Missing create traffic endpoint dest MAC address");
            cause_ie.cause_value = pfcp::CAUSE_VALUE_MANDATORY_IE_MISSING;
            offending_ie.offending_ie = PFCP_IE_MAC_ADDRESS;
            response.set(cause_ie);
            response.set(offending_ie);
            return false;
        }

        if (cte.pppoe_session_id.first) {
	    pppoe_session_id = cte.pppoe_session_id.second.pppoe_session_id;
            Logger::bngu_app().debug("CTE PPPoE SESSION ID: %d", cte.pppoe_session_id.second.pppoe_session_id);
        } else {
            Logger::bngu_app().error("Missing create traffic endpoint PPPoE Session ID");
            offending_ie.offending_ie = PFCP_IE_PPPOE_SESSION_ID;
            response.set(cause_ie);
            response.set(offending_ie);
            return false;
        }

        if (cte.s_tag.first && cte.s_tag.second.vid) {
            Logger::bngu_app().debug("CTE S-TAG: %d", cte.s_tag.second.svid_value);
            s_tag.svid_value = cte.s_tag.second.svid_value;
        } else {
            Logger::bngu_app().error("Missing create traffic endpoint S-TAG VID");
            offending_ie.offending_ie = PFCP_IE_S_TAG;
            response.set(cause_ie);
            response.set(offending_ie);
            return false;
        }

        if (cte.c_tag.first && cte.c_tag.second.vid) {
            Logger::bngu_app().debug("CTE C-TAG: %d", cte.c_tag.second.cvid_value);
            c_tag.cvid_value = cte.c_tag.second.cvid_value;
        } else {
            Logger::bngu_app().error("Missing create traffic endpoint C-TAG VID");
            offending_ie.offending_ie = PFCP_IE_C_TAG;
            response.set(cause_ie);
            response.set(offending_ie);
            return false;
        }
    } else {
        Logger::bngu_app().error("Missing create traffic endpoint IE");
        cause_ie.cause_value = pfcp::CAUSE_VALUE_MANDATORY_IE_MISSING;
        offending_ie.offending_ie = PFCP_IE_CREATE_TRAFFIC_ENDPOINT;
        response.set(cause_ie);
        response.set(offending_ie);
        return false;
    }

    response.set(cause_ie);

    Logger::bngu_app().info ("Printing AGF-UP Information Elements ");

    Logger::bngu_app().info ("Subscriber MAC Address: %02X:%02X:%02X:%02X:%02X:%02X",
			    subscriber_mac_address.destination_mac_address[0],
			    subscriber_mac_address.destination_mac_address[1],
			    subscriber_mac_address.destination_mac_address[2],
			    subscriber_mac_address.destination_mac_address[3],
			    subscriber_mac_address.destination_mac_address[4],
			    subscriber_mac_address.destination_mac_address[5]);
    Logger::bngu_app().info ("Subscriber IP Address: %s", ue_ip_addr_str);
    Logger::bngu_app().info ("Subscriber PPPOE Session Id: %d ", pppoe_session_id); 
    Logger::bngu_app().info ("Subscriber S-TAG: %d C-TAG: %d ", s_tag.svid_value, c_tag.cvid_value);
    Logger::bngu_app().info ("Subscriber GTPu Tunnel Id: 0x%X",local_fteid.teid);

    // If everything was ok with request
    if(cause_ie == pfcp::CAUSE_VALUE_REQUEST_ACCEPTED) {
        // Set UP F-SEID
        pfcp::fseid_t up_fseid_ie = {};
        up_fseid_ie.v4 = 1;
        memcpy (&up_fseid_ie.ipv4_address, bngu_in_addr_chr, sizeof (struct in_addr));
        up_fseid_ie.seid = 0; // TODO: Generate session ID
        response.set(up_fseid_ie);
        return true;
    }

    return false;
}

std::string bngu::get_upstream_dpdk_default_route(std::string upstream_route_ip_address,
        std::string bng_access_mac_address, std::string upstream_route_mac_address)
{
    char tmp_buffer[MAX_DPDK_CLI_MSG_SIZE]; // Used to populate messages

    sprintf (tmp_buffer, "pipeline upstream|routing table 0 rule add match lpm ipv4 %s 32 action fwd port 0 encap ether %s %s",
            upstream_route_ip_address.c_str(), bng_access_mac_address.c_str(), upstream_route_mac_address.c_str());
    return std::string(tmp_buffer);
}

void bngu::get_upstream_dpdk_commands_from_pfcp(
        pfcp::pfcp_session_establishment_request &request,
        std::vector<std::string> *commands, std::string bng_access_mac_address)
{
    char tmp_buffer[MAX_DPDK_CLI_MSG_SIZE]; // Used to populate messages
    char ue_ip_addr_str[INET_ADDRSTRLEN];

    pfcp::s_tag_t s_tag = {};
    pfcp::c_tag_t c_tag = {};
    pfcp::traffic_endpoint_id_t linked_traffic_endpoint_id = {};

    pfcp::create_traffic_endpoint cte;

    uint8_t *called_station_id;

    // Read values from request PDRs
    for (auto it : request.create_pdrs) {
        pfcp::create_pdr& pdr = it;
        pfcp::pdi pdi = pdr.pdi.second;

        if (pdi.ue_ip_address.first) {
            inet_ntop(AF_INET, &pdi.ue_ip_address.second.ipv4_address,
                    ue_ip_addr_str, sizeof(ue_ip_addr_str));
        }
    }

    // Read values from FARs
    for (auto it : request.create_fars) {
        pfcp::create_far& far = it;

        // Get forwarding parameters
        if (far.forwarding_parameters.first) {
            pfcp::forwarding_parameters fp = far.forwarding_parameters.second;

            // Traffic endpoint ID to match with create traffic endpoint it
            if (fp.linked_traffic_endpoint_id.first) {
                linked_traffic_endpoint_id = fp.linked_traffic_endpoint_id.second;
            }
        }
    }

    // Read values from Create Traffic Endpoint IE
    if (request.create_traffic_endpoint.first) {
        cte = request.create_traffic_endpoint.second;
        if(cte.traffic_endpoint_id.first &&
                cte.traffic_endpoint_id.second.traffic_endpoint_id == linked_traffic_endpoint_id.traffic_endpoint_id) {
            if(cte.mac_address.first && cte.mac_address.second.dest) {
                called_station_id = cte.mac_address.second.destination_mac_address;
            }

        } else {
            Logger::bngu_app().warn("Invalid match between create traffic endpoint id and linked ID in FAR");
            return;
        }
        if(cte.s_tag.first) {
            s_tag = cte.s_tag.second;
        }
        if(cte.c_tag.first) {
            c_tag = cte.c_tag.second;
        }
    }

    // Commands below should be commented/uncommented/modified according to DPDK ip pipeline configuration
    // Current setup uses default uplink route, so no rules are installed

    // // Populate vector of strings with commands
    // sprintf (tmp_buffer, "pipeline upstream|firewall table 0 rule add match acl priority 0 ipv4 %s 32 0.0.0.0 0 0 65535 0 65535 17 action fwd port 0",
    //         ue_ip_addr_str);
    // commands->push_back(std::string(tmp_buffer));

    // sprintf (tmp_buffer, "pipeline upstream|firewall table 0 rule add match acl priority 0 ipv4 %s 32 0.0.0.0 0 0 65535 0 65535 6 action fwd port 0",
    //         ue_ip_addr_str);
    // commands->push_back(std::string(tmp_buffer));

    // sprintf (tmp_buffer, "pipeline upstream|flow_clac table 0 rule add match hash qinq %d %d action fwd port 0 meter tc0 meter 0 policer g g y y r r",
    //         s_tag.svid_value, c_tag.cvid_value);
    // commands->push_back(std::string(tmp_buffer));

    // sprintf (tmp_buffer, "pipeline upstream|dscp table 0 rule add match acl priority 0 ipv4 %s 32 0.0.0.0 0 0 65535 0 65535 17 action fwd port 0 dscp 46",
    //         ue_ip_addr_str);
    // commands->push_back(std::string(tmp_buffer));

    // sprintf (tmp_buffer, "pipeline upstream|dscp table 0 rule add match acl priority 0 ipv4 %s 32 0.0.0.0 0 0 65535 0 65535 6 action fwd port 0 dscp 46",
    //         ue_ip_addr_str);
    // commands->push_back(std::string(tmp_buffer));

    // sprintf (tmp_buffer, "pipeline upstream|routing table 0 rule add match acl priority 0 ipv4 %s 32 0.0.0.0 0 0 65535 0 65535 17 action fwd port 0 encap ether %s %02X:%02X:%02X:%02X:%02X:%02X",
    //         ue_ip_addr_str, bng_access_mac_address.c_str(), called_station_id[0],
    //         called_station_id[1], called_station_id[2], called_station_id[3],
    //         called_station_id[4], called_station_id[5]);
    // commands->push_back(std::string(tmp_buffer));

    // sprintf (tmp_buffer, "pipeline upstream|routing table 0 rule add match acl priority 0 ipv4 %s 32 0.0.0.0 0 0 65535 0 65535 6 action fwd port 0 encap ether %s %02X:%02X:%02X:%02X:%02X:%02X",
    //         ue_ip_addr_str, bng_access_mac_address.c_str(), called_station_id[0],
    //         called_station_id[1], called_station_id[2], called_station_id[3],
    //         called_station_id[4], called_station_id[5]);
    // commands->push_back(std::string(tmp_buffer));
}


void bngu::get_downstream_dpdk_commands_from_pfcp(
        pfcp::pfcp_session_establishment_request &request,
        std::vector<std::string> *commands, std::string bng_core_mac_address,
        std::string downstream_route_mac_address)
{
    char tmp_buffer[MAX_DPDK_CLI_MSG_SIZE]; // Used to populate messages
    char ue_ip_addr_str[INET_ADDRSTRLEN];

    pfcp::s_tag_t s_tag = {};
    pfcp::c_tag_t c_tag = {};
    pfcp::mac_address_t epf_mac_address = {};
    pfcp::pppoe_session_id_t pppoe_session_id = {};

    pfcp::traffic_endpoint_id_t linked_traffic_endpoint_id = {};

    pfcp::create_traffic_endpoint cte;

    uint8_t *called_station_id;
    uint8_t *calling_station_id;

    uint16_t hqos_pipe;

    // Read values from request PDRs
    for (auto it : request.create_pdrs) {
        pfcp::create_pdr& pdr = it;
        pfcp::pdi pdi = pdr.pdi.second;

        // Destination IP from UE IP Address
        if (pdi.ue_ip_address.first) {
            inet_ntop(AF_INET, &pdi.ue_ip_address.second.ipv4_address,
                    ue_ip_addr_str, sizeof(ue_ip_addr_str));
            hqos_pipe = (uint16_t)(ntohl(pdi.ue_ip_address.second.ipv4_address.s_addr) & 0xFFF); // Set up pipe number based on last 12 bits
        }
        // Calling station ID from ethernet packet filter mac address
        if (pdi.ethernet_packet_filter.first && pdi.ethernet_packet_filter.second.mac_address.first) {
            epf_mac_address = pdi.ethernet_packet_filter.second.mac_address.second;
            if (epf_mac_address.dest) {
                calling_station_id = epf_mac_address.destination_mac_address;
            }
        }
    }

    // Read values from FARs
    for (auto it : request.create_fars) {
        pfcp::create_far& far = it;

        // Get forwarding parameters
        if (far.forwarding_parameters.first) {
            pfcp::forwarding_parameters fp = far.forwarding_parameters.second;

            // Traffic endpoint ID to match with create traffic endpoint it
            if (fp.linked_traffic_endpoint_id.first) {
                linked_traffic_endpoint_id = fp.linked_traffic_endpoint_id.second;
            }
        }
    }

    // Read values from Create Traffic Endpoint IE
    if (request.create_traffic_endpoint.first) {
        cte = request.create_traffic_endpoint.second;
        if(cte.traffic_endpoint_id.first &&
                cte.traffic_endpoint_id.second.traffic_endpoint_id == linked_traffic_endpoint_id.traffic_endpoint_id) {
            if(cte.mac_address.first && cte.mac_address.second.dest) {
                called_station_id = cte.mac_address.second.destination_mac_address;
            }
        } else {
            Logger::bngu_app().warn("Invalid match between create traffic endpoint id and linked ID in FAR");
            return;
        }
        if(cte.s_tag.first) {
            s_tag = cte.s_tag.second;
        }
        if(cte.c_tag.first) {
            c_tag = cte.c_tag.second;
        }
        if(cte.pppoe_session_id.first) {
            pppoe_session_id = cte.pppoe_session_id.second;
        }
    }

    // Commands below should be commented/uncommented/modified according to DPDK ip pipeline configuration

    // Populate vector of strings with commands
    // sprintf (tmp_buffer, "pipeline downstream|firewall table 0 rule add match acl priority 0 ipv4 0.0.0.0 0 %s 32 0 65535 0 65535 17 action fwd port 0",
    //         ue_ip_addr_str);
    // commands->push_back(std::string(tmp_buffer));

    // sprintf (tmp_buffer, "pipeline downstream|firewall table 0 rule add match acl priority 0 ipv4 0.0.0.0 0 %s 32 0 65535 0 65535 6 action fwd port 0",
    //         ue_ip_addr_str);
    // commands->push_back(std::string(tmp_buffer));


    sprintf (tmp_buffer, "pipeline downstream|hqos table 0 rule add match lpm ipv4 %s 32 action fwd port 0 tm subport 0 pipe %d",
            ue_ip_addr_str, hqos_pipe);
    commands->push_back(std::string(tmp_buffer));

    // sprintf (tmp_buffer, "pipeline downstream|routing table 0 rule add match acl priority 0 ipv4 0.0.0.0 0 %s 32 0 65535 0 65535 17 action fwd port 0 encap qinq_pppoe %02X:%02X:%02X:%02X:%02X:%02X %02X:%02X:%02X:%02X:%02X:%02X 7 0 %d 7 0 %d %d",
    //         ue_ip_addr_str, calling_station_id[0], calling_station_id[1],
    //         calling_station_id[2], calling_station_id[3], calling_station_id[4],
    //         calling_station_id[5], called_station_id[0], called_station_id[1],
    //         called_station_id[2], called_station_id[3], called_station_id[4],
    //         called_station_id[5], s_tag.svid_value, c_tag.cvid_value,
    //         pppoe_session_id.pppoe_session_id);
    sprintf (tmp_buffer, "pipeline downstream|routing table 0 rule add match lpm ipv4 %s 32 action fwd port 0 encap qinq_pppoe %02X:%02X:%02X:%02X:%02X:%02X %02X:%02X:%02X:%02X:%02X:%02X 7 0 %d 7 0 %d %d",
            ue_ip_addr_str, calling_station_id[0], calling_station_id[1],
            calling_station_id[2], calling_station_id[3], calling_station_id[4],
            calling_station_id[5], called_station_id[0], called_station_id[1],
            called_station_id[2], called_station_id[3], called_station_id[4],
            called_station_id[5], s_tag.svid_value, c_tag.cvid_value,
            pppoe_session_id.pppoe_session_id);
    commands->push_back(std::string(tmp_buffer));
}

void bngu::get_upstream_dpdk_delete_commands(uint16_t s_tag, uint16_t c_tag,
        std::vector<std::string> *commands)
{
    char tmp_buffer[MAX_DPDK_CLI_MSG_SIZE]; // Used to populate messages

    // sprintf(tmp_buffer, "pipeline downstream|flow_clac table 0 rule delete match hash qinq %d %d", s_tag, c_tag);
    // commands->push_back(std::string(tmp_buffer));
}

void bngu::get_downstream_dpdk_delete_commands(struct in_addr ipv4_address,
        std::vector<std::string> *commands)
{
    char tmp_buffer[MAX_DPDK_CLI_MSG_SIZE]; // Used to populate messages
    char ip_addr_str[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &ipv4_address, ip_addr_str, sizeof(ip_addr_str));

    sprintf(tmp_buffer, "pipeline downstream|hqos table 0 rule delete match lpm ipv4 %s 32", ip_addr_str);
    commands->push_back(std::string(tmp_buffer));

    sprintf(tmp_buffer, "pipeline downstream|routing table 0 rule delete match lpm ipv4 %s 32", ip_addr_str);
    commands->push_back(std::string(tmp_buffer));
}

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
#include "bngc_pfcp.hpp"
#include "bngc_pfcp_association.hpp"

using namespace bngc;

extern itti_mw *itti_inst;
extern bngc_pfcp *bngc_pfcp_inst;

// Adapted from pgw_pfcp_association.cpp
void pfcp_association::notify_add_session(const pfcp::fseid_t& cp_fseid)
{
    std::unique_lock<std::mutex> l(m_sessions);
    sessions.insert(cp_fseid);
}

bool pfcp_association::has_session(const pfcp::fseid_t& cp_fseid)
{
    std::unique_lock<std::mutex> l(m_sessions);
    auto it = sessions.find(cp_fseid);
    if (it != sessions.end()) {
        return true;
    } else {
        return false;
    }
}

void pfcp_association::notify_del_session(const pfcp::fseid_t& cp_fseid)
{
    std::unique_lock<std::mutex> l(m_sessions);
    sessions.erase(cp_fseid);
}

bool pfcp_associations::add_association(pfcp::node_id_t& node_id,
        pfcp::recovery_time_stamp_t& recovery_time_stamp)
{
    std::shared_ptr<pfcp_association> sa = std::shared_ptr<pfcp_association>(nullptr);
    if (get_association(node_id, sa)) {
        itti_inst->timer_remove(sa->timer_heartbeat); // Remove previous heartbeat timer
        sa->recovery_time_stamp = recovery_time_stamp; // Update recovery timestamp
    } else {
        pfcp_association* association = new pfcp_association(node_id,
                recovery_time_stamp);
        sa = std::shared_ptr<pfcp_association>(association);
        std::size_t hash_node_id = std::hash<pfcp::node_id_t>{}(node_id);
        associations.insert((int32_t)hash_node_id, sa);
    }
    trigger_heartbeat_request_procedure(sa); // Always trigger heartbeat request procedure
    return true;
}

bool pfcp_associations::get_association(const pfcp::node_id_t& node_id,
        std::shared_ptr<pfcp_association>&  sa) const
{
    std::size_t hash_node_id = std::hash<pfcp::node_id_t>{}(node_id);
    auto pit = associations.find((int32_t)hash_node_id);
    if ( pit == associations.end() )
        return false;
    else {
        sa = pit->second;
        return true;
    }
}

bool pfcp_associations::get_association(const pfcp::fseid_t& cp_fseid,
        std::shared_ptr<pfcp_association>&  sa) const
{
    folly::AtomicHashMap<int32_t, std::shared_ptr<pfcp_association>>::iterator it;

    FOR_EACH (it, associations) {
        std::shared_ptr<pfcp_association> a = it->second;
        if (it->second->has_session(cp_fseid)) {
        sa = it->second;
        return true;
        }
    }
    return false;
}

void pfcp_associations::notify_add_session(const pfcp::node_id_t& node_id,
        const pfcp::fseid_t& cp_fseid)
{
    std::shared_ptr<pfcp_association> sa = {};
    if (get_association(node_id, sa)) {
        Logger::bngc_app().debug("notify_add_session: Adding session %d", cp_fseid.seid);
        sa->notify_add_session(cp_fseid);
    }
}

void pfcp_associations::notify_del_session(const pfcp::fseid_t& cp_fseid)
{
    std::shared_ptr<pfcp_association> sa = {};
    if (get_association(cp_fseid, sa)) {
        Logger::bngc_app().debug("notify_del_session: Deleting session %d", cp_fseid.seid);
        sa->notify_del_session(cp_fseid);
    }
}

void pfcp_associations::trigger_heartbeat_request_procedure(
        std::shared_ptr<pfcp_association>& s)
{
  s->timer_heartbeat = itti_inst->timer_setup(PFCP_ASSOCIATION_HEARTBEAT_INTERVAL_SEC,
        0, TASK_BNGC_PFCP, TASK_BNGC_PFCP_TRIGGER_HEARTBEAT_REQUEST,
        s->hash_node_id);
}

void pfcp_associations::initiate_heartbeat_request(timer_id_t timer_id,
        uint64_t arg2_user)
{
    size_t hash_node_id = (size_t)arg2_user;
    auto pit = associations.find((int32_t)hash_node_id);
    if (pit == associations.end()) {
        Logger::bngc_pfcp().warn("PFCP HEARTBEAT PROCEDURE not found for node hash %u",
                hash_node_id);
        return;
    }

    Logger::bngc_pfcp().debug("PFCP HEARTBEAT PROCEDURE hash %u starting",
            hash_node_id);
    pit->second->num_retries_timer_heartbeat = 0;
    bngc_pfcp_inst->send_heartbeat_request(pit->second);
}

void pfcp_associations::timeout_heartbeat_request(timer_id_t timer_id,
        uint64_t arg2_user)
{
    size_t hash_node_id = (size_t)arg2_user;
    auto pit = associations.find((int32_t)hash_node_id);
    if (pit == associations.end()) {
        Logger::bngc_pfcp().warn("PFCP HEARTBEAT PROCEDURE not found for node hash %u",
            hash_node_id);
        return;
    }

    if (pit->second->num_retries_timer_heartbeat < PFCP_ASSOCIATION_HEARTBEAT_MAX_RETRIES) {
        Logger::bngc_pfcp().warn("PFCP HEARTBEAT PROCEDURE hash %u TIMED OUT (retry %d)",
            hash_node_id, pit->second->num_retries_timer_heartbeat);
        pit->second->num_retries_timer_heartbeat++;
        // Trigger sending heartbeat again in case 5 seconds have passed (after 3 internal pfcp retries)
        bngc_pfcp_inst->send_heartbeat_request(pit->second);
    } else {
        Logger::bngc_pfcp().warn( "PFCP HEARTBEAT PROCEDURE FAILED after %d retries! Deleting association",
            PFCP_ASSOCIATION_HEARTBEAT_MAX_RETRIES);
        associations.erase((uint32_t)hash_node_id);
        // TODO: Implement cleanup for sessions?
    }
}

void pfcp_associations::handle_receive_heartbeat_response(const uint64_t trxn_id)
{
    folly::AtomicHashMap<int32_t, std::shared_ptr<pfcp_association>>::iterator it;

    FOR_EACH (it, associations) {
        std::shared_ptr<pfcp_association> a = it->second;
        if (it->second->trxn_id_heartbeat == trxn_id) {
            itti_inst->timer_remove(it->second->timer_heartbeat);
            trigger_heartbeat_request_procedure(it->second);
            return;
        }
    }
}

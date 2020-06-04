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
#include "bngu_pfcp.hpp"
#include "bngu_pfcp_association.hpp"

using namespace bngu;

extern itti_mw *itti_inst;
extern bngu_pfcp *bngu_pfcp_inst;

// Adaptation of spgwu_pfcp_association.cpp for pfcp bng

void pfcp_association::notify_add_session(const pfcp::fseid_t& cp_fseid)
{
    std::unique_lock<std::mutex> l(m_sessions);
    sessions.insert(cp_fseid);
}

bool pfcp_association::has_session(const pfcp::fseid_t& cp_fseid) const
{
    std::unique_lock<std::mutex> l(m_sessions);
    auto it = sessions.find(cp_fseid);
    return it != sessions.end();
}

void pfcp_association::notify_del_session(const pfcp::fseid_t& cp_fseid)
{
    std::unique_lock<std::mutex> l(m_sessions);
    sessions.erase(cp_fseid);
}

void pfcp_associations::trigger_heartbeat_request_procedure(std::shared_ptr<pfcp_association>& s)
{
    s->timer_heartbeat = itti_inst->timer_setup(PFCP_ASSOCIATION_HEARTBEAT_INTERVAL_SEC,
            0, TASK_BNGU_PFCP, TASK_BNGU_PFCP_TRIGGER_HEARTBEAT_REQUEST,
            s->hash_node_id);
}

void pfcp_associations::initiate_heartbeat_request(timer_id_t timer_id,
        uint64_t arg2_user)
{
    size_t hash = (size_t)arg2_user;
    for (auto it : associations) {
        if (it.second->hash_node_id == hash) {
            Logger::bngu_pfcp().debug("PFCP HEARTBEAT PROCEDURE hash %u starting", hash);
            it.second->num_retries_timer_heartbeat = 0;
            bngu_pfcp_inst->send_heartbeat_request(it.second);
            return;
        }
    }
    Logger::bngu_pfcp().warn("PFCP HEARTBEAT PROCEDURE not found for node hash %u",
                hash);
}

void pfcp_associations::timeout_heartbeat_request(timer_id_t timer_id,
        uint64_t arg2_user)
{
    size_t hash = (size_t)arg2_user;
    for (auto it : associations) {
        if (it.second->hash_node_id == hash) {
            Logger::bngu_pfcp().warn("PFCP HEARTBEAT PROCEDURE hash %u TIMED OUT", hash);
            if (it.second->num_retries_timer_heartbeat < PFCP_ASSOCIATION_HEARTBEAT_MAX_RETRIES) {
                it.second->num_retries_timer_heartbeat++;
                // Trigger sending heartbeat again in case 5 seconds have passed (after 3 internal pfcp retries)
                bngu_pfcp_inst->send_heartbeat_request(it.second);
            } else {
                Logger::bngu_pfcp().warn( "PFCP HEARTBEAT PROCEDURE FAILED after %d retries!",
                        PFCP_ASSOCIATION_HEARTBEAT_MAX_RETRIES);
                // it.second->del_sessions(); // TODO: Delete sessions on timeout?
                pfcp::node_id_t node_id = it.second->node_id;
                std::size_t hash_node_id = it.second->hash_node_id;
                associations.erase((uint32_t)hash_node_id);
                // TODO: Handle association setup again to re-establish connectivity
                break;
            }
        }
    }
}

void pfcp_associations::handle_receive_heartbeat_response(const uint64_t trxn_id)
{
    for (auto it : associations) {
        if (it.second->trxn_id_heartbeat == trxn_id) {
            itti_inst->timer_remove(it.second->timer_heartbeat);
            trigger_heartbeat_request_procedure(it.second);
            return;
        }
    }
    Logger::bngu_pfcp().warn("PFCP HEARTBEAT PROCEDURE trxn_id %d NOT FOUND", trxn_id);
}

void pfcp_associations::create_pending_association(const pfcp::node_id_t& node_id)
{
    for (std::vector<std::shared_ptr<pfcp_association>>::iterator it=pending_associations.begin();
            it < pending_associations.end(); ++it) {
        if ((*it)->node_id == node_id) {
            pending_associations.erase(it);
            break;
        }
    }
    pfcp_association* association = new pfcp_association(node_id);
    std::shared_ptr<pfcp_association> s = std::shared_ptr<pfcp_association>(association);
    pending_associations.push_back(s);
}

bool pfcp_associations::remove_pending_association(pfcp::node_id_t& node_id, std::shared_ptr<pfcp_association>& s)
{
    for (std::vector<std::shared_ptr<pfcp_association>>::iterator it=pending_associations.begin();
            it < pending_associations.end(); ++it) {
        if ((*it)->node_id == node_id) {
            s = *it;
            pending_associations.erase(it);
            return true;
        }
    }
    return false;
}

bool pfcp_associations::add_association(pfcp::node_id_t& node_id,
        pfcp::recovery_time_stamp_t& recovery_time_stamp)
{
    Logger::bngu_pfcp().debug("Adding new PFCP association");
    std::shared_ptr<pfcp_association>  sa = {};
    if (remove_pending_association(node_id, sa)) {
        sa->recovery_time_stamp = recovery_time_stamp;
        std::size_t hash_node_id = std::hash<pfcp::node_id_t>{}(node_id);
        associations.insert((int32_t)hash_node_id, sa);
        trigger_heartbeat_request_procedure(sa);
        return true;
    }
    Logger::bngu_pfcp().warn("Couldn't find pending association setup");
    return false;
}

bool pfcp_associations::get_association(const pfcp::node_id_t& node_id,
        std::shared_ptr<pfcp_association>&  sa) const
{
    std::size_t hash_node_id = std::hash<pfcp::node_id_t>{}(node_id);
    auto pit = associations.find((int32_t)hash_node_id);
    if (pit == associations.end()) {
        Logger::bngu_pfcp().warn("Couldn't find association");
        return false;
    }
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
    Logger::bngu_pfcp().warn("Couldn't find association");
    return false;
}

void pfcp_associations::notify_add_session(const pfcp::node_id_t& node_id,
        const pfcp::fseid_t& cp_fseid)
{
    std::shared_ptr<pfcp_association> sa = {};
    if (get_association(node_id, sa)) {
        sa->notify_add_session(cp_fseid);
    }
}

void pfcp_associations::notify_del_session(const pfcp::fseid_t& cp_fseid)
{
    std::shared_ptr<pfcp_association> sa = {};
    if (get_association(cp_fseid, sa)) {
        sa->notify_del_session(cp_fseid);
    }
}

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
#ifndef FILE_BNGU_PFCP_ASSOCIATION_HPP_SEEN
#define FILE_BNGU_PFCP_ASSOCIATION_HPP_SEEN

#include "3gpp_29.244.h"
#include "itti.hpp"

#include <folly/AtomicHashMap.h>
#include <mutex>

namespace bngu {

#define PFCP_ASSOCIATION_HEARTBEAT_INTERVAL_SEC 10
#define PFCP_ASSOCIATION_HEARTBEAT_MAX_RETRIES 2
#define PFCP_MAX_ASSOCIATIONS 16

// (Adaptation of spgwu_pfcp_association.hpp for pfcp bng)
class pfcp_association {
public:
    pfcp::node_id_t node_id;
    std::size_t hash_node_id;
    pfcp::recovery_time_stamp_t recovery_time_stamp;
    //std::pair<bool,pfcp::cp_function_features_s> function_features;

    mutable std::mutex m_sessions;
    std::set<pfcp::fseid_t> sessions;

    timer_id_t timer_heartbeat;
    int num_retries_timer_heartbeat;
    uint64_t trxn_id_heartbeat;

    explicit pfcp_association(const pfcp::node_id_t& node_id) :
        node_id(node_id), recovery_time_stamp(), m_sessions(), sessions() {
        hash_node_id = std::hash<pfcp::node_id_t>{}(node_id);
        timer_heartbeat = ITTI_INVALID_TIMER_ID;
        num_retries_timer_heartbeat = 0;
        trxn_id_heartbeat = 0;
    }

    pfcp_association(const pfcp::node_id_t& node_id,
            pfcp::recovery_time_stamp_t& recovery_time_stamp) : node_id(node_id),
            recovery_time_stamp(recovery_time_stamp), m_sessions(), sessions() {
        hash_node_id = std::hash<pfcp::node_id_t>{}(node_id);
        timer_heartbeat = ITTI_INVALID_TIMER_ID;
        num_retries_timer_heartbeat = 0;
        trxn_id_heartbeat = 0;
    }

    // Not used at the moment, as the session state is kept in accel-ppod/radius
    void notify_add_session(const pfcp::fseid_t& cp_fseid);
    bool has_session(const pfcp::fseid_t& cp_fseid) const ;
    void notify_del_session(const pfcp::fseid_t& cp_fseid);
};

class pfcp_associations {
private:
    std::vector<std::shared_ptr<pfcp_association>> pending_associations;
    folly::AtomicHashMap<int32_t, std::shared_ptr<pfcp_association>> associations;

    pfcp_associations() : associations(PFCP_MAX_ASSOCIATIONS), pending_associations() {};
    void trigger_heartbeat_request_procedure(std::shared_ptr<pfcp_association>& s);
    bool remove_pending_association(pfcp::node_id_t& node_id,
            std::shared_ptr<pfcp_association>& s);

public:
    static pfcp_associations& get_instance()
    {
        static pfcp_associations instance;
        return instance;
    }

    void create_pending_association(const pfcp::node_id_t& node_id);
    bool add_association(pfcp::node_id_t& node_id,
            pfcp::recovery_time_stamp_t& recovery_time_stamp);
    bool get_association(const pfcp::node_id_t& node_id,
            std::shared_ptr<pfcp_association>&  sa) const;
    bool get_association(const pfcp::fseid_t& cp_fseid,
            std::shared_ptr<pfcp_association>&  sa) const;

    // Not used at the moment, as the session state is kept in accel-ppod/radius
    void notify_add_session(const pfcp::node_id_t& node_id,
            const pfcp::fseid_t& cp_fseid);
    void notify_del_session(const pfcp::fseid_t& cp_fseid);

    void initiate_heartbeat_request(timer_id_t timer_id, uint64_t arg2_user);
    void timeout_heartbeat_request(timer_id_t timer_id, uint64_t arg2_user);

    void handle_receive_heartbeat_response(const uint64_t trxn_id);
};

}

#endif /* FILE_BNGU_PFCP_ASSOCIATION_HPP_SEEN */

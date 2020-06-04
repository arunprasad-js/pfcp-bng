#include "itti_msg.hpp"

class itti_dpdk_send_msg_request : public itti_msg {
public:
    itti_dpdk_send_msg_request(const task_id_t origin, const task_id_t destination, 
            std::string dpdk_cli_msg) : itti_msg(BNGU_DPDK_SEND_MESSAGE_REQUEST, 
            origin, destination) {
        this->dpdk_cli_msg = dpdk_cli_msg;
    }

    const char* get_msg_name() {return typeid(itti_dpdk_send_msg_request).name();};

     std::string dpdk_cli_msg;
};

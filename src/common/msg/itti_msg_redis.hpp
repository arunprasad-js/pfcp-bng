#include "itti_msg.hpp"

class itti_new_redis_msg : public itti_msg {
public:
    itti_new_redis_msg(const task_id_t origin, const task_id_t destination,
            std::string redis_msg) : itti_msg(NEW_REDIS_MSG,
            origin, destination) {
        this->redis_msg = redis_msg;
    }

    const char* get_msg_name() {return typeid(itti_new_redis_msg).name();};

     std::string redis_msg;
};

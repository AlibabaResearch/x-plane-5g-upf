#ifndef RDMA_SERVER_CRAFTER_H
#define RDMA_SERVER_CRAFTER_H

#include <crafter.h>

#include "common/common.h"


class PacketCrafter {
private:
    std::shared_ptr<spdlog::logger> logger = nullptr;

public:
    PacketCrafter();

    ~PacketCrafter();

    void sendRDMAInfoPacket(void *, uint8_t, const std::string &);
};

#endif

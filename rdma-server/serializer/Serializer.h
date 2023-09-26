#ifndef RDMA_SERVER_SERIALIZER_H
#define RDMA_SERVER_SERIALIZER_H

#pragma once

#include <list>

#include "../common/common.h"

class Serializer {
public:
    static std::pair<uint8_t *, std::size_t> *serializeRDMAQPInfo(uint16_t, uint16_t, uint32_t);

    static std::pair<uint8_t *, std::size_t> *serializeRDMAMemInfo(uint16_t, uintptr_t, uint32_t);

    static std::pair<uint8_t *, std::size_t> *serializeRDMAEthInfo(uint16_t, uint64_t, uint32_t);
};

#endif

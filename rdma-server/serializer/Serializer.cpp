#include "Serializer.h"

std::pair<uint8_t *, std::size_t> *Serializer::serializeRDMAQPInfo(uint16_t enableTimer, uint16_t idx,
                                                                   uint32_t destQPNum) {
    const std::size_t totalSize = sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint32_t);
    auto *payload = new uint8_t[totalSize];
    uint8_t *ptr = payload;

    /* Transform everything to big endian */
    enableTimer = htobe16(enableTimer);
    idx = htobe16(idx);
    destQPNum = htobe32(destQPNum);

    /* Set RDMA Info Code = 0x00 (QP) */
    memset(ptr, 0x00, sizeof(uint8_t));
    ptr += sizeof(uint8_t); /* Go to next field */
    std::memcpy(ptr, &enableTimer, sizeof(uint16_t));
    ptr += sizeof(uint16_t); /* Go to next field */
    std::memcpy(ptr, &idx, sizeof(uint16_t));
    ptr += sizeof(uint16_t); /* Go to next field */
    std::memcpy(ptr, &destQPNum, sizeof(uint32_t));

    return new std::pair<uint8_t *, std::size_t>(payload, totalSize);
}

std::pair<uint8_t *, std::size_t> *Serializer::serializeRDMAMemInfo(uint16_t serverId, uintptr_t addr, uint32_t key) {
    const std::size_t totalSize = sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uintptr_t) + sizeof(uint32_t);
    auto *payload = new uint8_t[totalSize];
    uint8_t *ptr = payload;

    /* Transform everything to big endian */
    serverId = htobe16(serverId);
    addr = htobe64(addr);
    key = htobe32(key);

    /* Set RDMA Info Code = 0x01 (MEM) */
    memset(ptr, 0x01, sizeof(uint8_t));
    ptr += sizeof(uint8_t); /* Go to next field */
    std::memcpy(ptr, &serverId, sizeof(uint16_t));
    ptr += sizeof(uint16_t); /* Go to next field */
    std::memcpy(ptr, &addr, sizeof(uintptr_t));
    ptr += sizeof(uintptr_t); /* Go to next field */
    std::memcpy(ptr, &key, sizeof(uint32_t));

    return new std::pair<uint8_t *, std::size_t>(payload, totalSize);
}

std::pair<uint8_t *, std::size_t> *Serializer::serializeRDMAEthInfo(uint16_t serverId, uint64_t macAddr,
                                                                    uint32_t ipAddr) {
    const std::size_t totalSize = sizeof(uint8_t) + sizeof(uint16_t) + sizeof(uint64_t) + sizeof(uint32_t);
    auto *payload = new uint8_t[totalSize];
    uint8_t *ptr = payload;

    /* Transform everything to big endian */
    serverId = htobe16(serverId);
    macAddr = htobe64(macAddr);
    ipAddr = htobe32(ipAddr);

    /* Set RDMA Info Code = 0x02 (ETH) */
    memset(ptr, 0x02, sizeof(uint8_t));
    ptr += sizeof(uint8_t); /* Go to next field */
    std::memcpy(ptr, &serverId, sizeof(uint16_t));
    ptr += sizeof(uint16_t); /* Go to next field */
    std::memcpy(ptr, &macAddr, sizeof(uint64_t));
    ptr += sizeof(uintptr_t); /* Go to next field */
    std::memcpy(ptr, &ipAddr, sizeof(uint32_t));

    return new std::pair<uint8_t *, std::size_t>(payload, totalSize);
}
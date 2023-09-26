#ifndef RDMA_SERVER_IBNETWORKING_H
#define RDMA_SERVER_IBNETWORKING_H

#include <algorithm>
#include <fstream>
#include <dirent.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <net/if_arp.h>

#include "../common/common.h"

class IBNetworking {
public:
    static IBNetworking &getInstance();

    IBNetworking(IBNetworking const &) = delete;

    void operator=(IBNetworking const &) = delete;

    ~IBNetworking();

    struct ibv_device *getDeviceByName(std::string);

    std::string getDeviceNetDevice(ibv_device *);

    std::pair<uint8_t, struct ibv_port_attr *> *getDevicePort(struct ibv_context *, ibv_device *);

    uint64_t getDeviceMacAddress(ibv_device *);

    uint32_t getDeviceIpAddress(ibv_device *);

    struct ibv_gid_entry *getDeviceGid(struct ibv_context *, ibv_device *, std::pair<uint8_t, struct ibv_port_attr *> *);

    void addFakeARPEntry(uint32_t, const std::string &);

private:
    const std::string netPath = "/sys/class/net";

    IBNetworking();

    std::shared_ptr<spdlog::logger> logger = nullptr;
};

#endif //RDMA_SERVER_IBNETWORKING_H

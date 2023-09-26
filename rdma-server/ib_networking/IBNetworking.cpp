#include "IBNetworking.h"

IBNetworking::IBNetworking() {
    this->logger = spdlog::stdout_logger_mt("IBNetworking");
}

IBNetworking::~IBNetworking() {
    this->logger.reset();

    spdlog::drop("IBNetworking");
}

IBNetworking &IBNetworking::getInstance() {
    static IBNetworking instance;
    return instance;
}

struct ibv_device *IBNetworking::getDeviceByName(std::string device) {
    struct ibv_device **availableDevices = ibv_get_device_list(nullptr);
    if (!availableDevices)
        return nullptr;

    struct ibv_device *dev = nullptr;
    for (uint32_t i = 0; availableDevices[i]; ++i) {
        std::string devName = std::string(ibv_get_device_name(availableDevices[i]));
        if (devName.compare(device) == 0) {
            dev = availableDevices[i];
            break;
        }
    }

    if (!dev)
        return nullptr;

    ibv_free_device_list(availableDevices);

    return dev;
}

std::pair<uint8_t, struct ibv_port_attr *> *IBNetworking::getDevicePort(struct ibv_context *context,
                                                                        ibv_device *device) {
    //return NULL;
    std::string netDevice = this->getDeviceNetDevice(device);

    //return NULL;
    uint8_t port = 0;
    uint8_t port1 = 0;
    /*
    std::ifstream devIdStream(this->netPath + "/" + netDevice + "/dev_id");
    if (devIdStream.good()) {
        port1 = 0;
        std::ifstream devPortStream(this->netPath + "/" + netDevice + "/dev_port");
        if (devPortStream.good()) {
            std::string devPort;
            getline(devPortStream, devPort);
            port1 = std::stoi(devPort);
        }
        devPortStream.close();

        std::string devId;
        getline(devIdStream, devId);
        sscanf(devId.c_str(), "%x", &port);
    } else {
        this->logger->info("Could not find port for device {0}", device->name);
    }
    devIdStream.close();
    */
    //return NULL;
    this->logger->info("port1 is: {0} port is: {1}", port1, port);
    port = ((port1 > port) ? port1 : port) + 1;

    this->logger->info("Device {0} port is: {1}", device->name, port);

    auto *portAttr = new struct ibv_port_attr;
    ibv_query_port(context, port, portAttr);
    this->logger->info("ib1");
 
    //return NULL;
    std::pair<uint8_t, struct ibv_port_attr *> *portInfo = new std::pair<uint8_t, struct ibv_port_attr *>(port, portAttr);

    this->logger->info("ib2"); 

    return portInfo;//new std::pair<uint8_t, struct ibv_port_attr *>(port, portAttr);
}

std::string IBNetworking::getDeviceNetDevice(ibv_device *device) {
    /* Read IB device resource identifier from /sys/class/net/{iface}/device/resource */
    std::string ibResource;
    std::ifstream ibResourceStream(std::string(device->dev_path) + "/device/resource");
    while (!ibResourceStream.eof()) {
        std::string data;
        ibResourceStream >> data;
        ibResource += data;
    }
    ibResourceStream.close();

    std::string netDevice = "";

    struct dirent *entry;
    DIR *dir = opendir(this->netPath.c_str());
    while ((entry = readdir(dir)) != nullptr) {
        /* Convert char * into a std::string and skip useless entries */
        std::string ifaceName = std::string(entry->d_name);
        if (ifaceName == "." || ifaceName == ".." || ifaceName == "lo")
            continue;

        /* Read net device resource identifier from /sys/class/net/{iface}/device/resource */
        std::string netResource;
        std::ifstream netResourceStream(this->netPath + "/" + ifaceName + "/device/resource");
        if (!netResourceStream.good()) {
            netResourceStream.close();
            continue;
        }
        while (!netResourceStream.eof()) {
            std::string data;
            netResourceStream >> data;
            netResource += data;
        }
        netResourceStream.close();

        /* This device is not bound to the IB one */
        if (ibResource.compare(netResource) != 0)
            continue;

        /* We found the net device corresponding to the IB one, return */
        netDevice = ifaceName;
        this->logger->info("Found net device for interface {0}: {1}.", device->name, netDevice);
        break;
    }

    closedir(dir);

    return netDevice;
}

uint64_t IBNetworking::getDeviceMacAddress(ibv_device *device) {
    std::string netDevice = this->getDeviceNetDevice(device);

    /* Read interface MAC Address from /sys/class/net/{iface}/address */
    std::string ifaceMacAddress;
    std::ifstream addressFileStream(this->netPath + "/" + netDevice + "/address");
    getline(addressFileStream, ifaceMacAddress);
    addressFileStream.close();

    /* Remove ":" from the MAC Address string to have a plain 48bit hex number */
    ifaceMacAddress.erase(std::remove(ifaceMacAddress.begin(), ifaceMacAddress.end(), ':'), ifaceMacAddress.end());

    /* Convert hex string to uint64 */
    uint64_t numericIfaceMacAddress;
    sscanf(ifaceMacAddress.c_str(), "%lx", &numericIfaceMacAddress);

    this->logger->info("MAC Address of device {0} is: {1:x}", device->name, numericIfaceMacAddress);

    return numericIfaceMacAddress;
}

uint32_t IBNetworking::getDeviceIpAddress(ibv_device *device) {
    std::string netDevice = this->getDeviceNetDevice(device);

    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    auto *ifr = new struct ifreq;
    ifr->ifr_addr.sa_family = AF_INET;
    strncpy(ifr->ifr_name, netDevice.c_str(), IFNAMSIZ - 1);
    ioctl(fd, SIOCGIFADDR, ifr);

    close(fd);

    uint32_t ipAddress = ((struct sockaddr_in *) &ifr->ifr_addr)->sin_addr.s_addr;
    ipAddress = be32toh(ipAddress);

    this->logger->info("IP Address of device {0} is: {1:x}", device->name, ipAddress);

    return ipAddress;
}

struct ibv_gid_entry *IBNetworking::getDeviceGid(struct ibv_context *context, ibv_device *device,
                                                 std::pair<uint8_t, struct ibv_port_attr *> *portInfo) {
    uint32_t ipAddress = this->getDeviceIpAddress(device);

    for (uint8_t gidNum = 0; gidNum < portInfo->second->gid_tbl_len - 1; ++gidNum) {
        auto *entry = new struct ibv_gid_entry;
        ibv_query_gid_ex(context, portInfo->first, gidNum, entry, 0);

        if (entry->gid_type == ibv_gid_type::IBV_GID_TYPE_ROCE_V2) {
            if (entry->gid.raw[0] == 0xfe && entry->gid.raw[1] == 0x80) // IPv6, skip
                continue;

            if (entry->gid.raw[10] == 0xff && entry->gid.raw[11] == 0xff) { // IPv4, check if they match
                uint32_t gidAddr = entry->gid.raw[12] << 24 | entry->gid.raw[13] << 16 |
                                   entry->gid.raw[14] << 8 | entry->gid.raw[15];

                if (gidAddr == ipAddress) {
                    this->logger->info("GID of device {0} is: {1:x}", device->name, gidNum);

                    return entry;
                }
            }
        }

        delete (entry);
    }

    return nullptr;
}

void IBNetworking::addFakeARPEntry(uint32_t ipAddr, const std::string &interface) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);

    auto *req = new struct arpreq;
    memset(req, 0, sizeof(struct arpreq));

    auto *macToAssign = new char[14];
    memset(macToAssign, 0, 14);
    macToAssign[5] = 0x01;
    std::memcpy(&req->arp_ha.sa_data, macToAssign, 14);
    strcpy(req->arp_dev, interface.c_str());

    auto *sin = (struct sockaddr_in *) &req->arp_pa;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = ipAddr;

    req->arp_flags = ATF_COM;

    ioctl(fd, SIOCSARP, req);

    close(fd);

    delete (req);
    delete[] (macToAssign);

    this->logger->info("Set fake ARP Entry for interface {0}", interface);
}
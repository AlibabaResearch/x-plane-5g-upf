#include "Server.h"

Server::Server(std::string device, uint16_t idx, uint16_t numaNode, uint16_t qps,
               uint16_t minDistrValue, uint16_t maxDistrValue) :
        device{std::move(device)}, idx{idx}, numaNode{numaNode}, qps{qps},
        minDistrValue{minDistrValue}, maxDistrValue{maxDistrValue} {
    this->logger = spdlog::stdout_logger_mt("Server");
}

Server::~Server() {
    this->crafter.reset();

    if (this->connection != nullptr) {
        delete (this->connection->socketConnectionThread);
        BufferManager::getInstance().destroy(connection, this->numaNode);
        ConnectionManager::getInstance().destroy(this->connection);
    }

    delete (this->qpAttrs);

    spdlog::drop("Server");
}

void Server::disp_mem(uintptr_t addr) {
    int content_length = 16;
    while (true) {
    printf("\n--------------------content check---------------------\n");
    for(int i = 0; i < content_length; i++) {
        if (i% 4 == 0 && i > 0) printf("\n");
        printf("%02x ", *(((char *)addr) + i));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    } 
}

void Server::hex_dump(uintptr_t addr,int len){
    uint8_t* current =(uint8_t*)addr;
    printf("Print %d values in 0x%x\n",len,addr);
    for(int i = 0; i < len; i++){
        printf("%02x ", *(current));
        if(i%10 == 0) printf("\n");
        current++;
    }

}

void Server::init_ue_pdr(uintptr_t addr) {
    int entry_num = 0x20000;
    int entry_slot_len = 4096;
    int pdr_round = 8;
    int type_offset = 0;
    int idle_offset = 15;
    uint8_t* current = (uint8_t*) addr;
    uint64_t ue_flow_entry_num = 0x100000; 

    for(int i = 0; i < entry_num; i++){
        *(current + type_offset) = 0x01;
        *(current + 15) = 0x4a;
        current += entry_slot_len;
    }
    for(int j = 0; j < pdr_round; j++){
        for(int i = 0; i < entry_num; i++){
            *(current + type_offset) = 0x02;
            current += entry_slot_len;
        }
    }
    //ue flow size
    for(int i = 0; i < ue_flow_entry_num; i++){
        *(current + type_offset) = 0x03;
        current += entry_slot_len;                                   
    }     

    /*for (int i = 0; i < entry_num; i++) *((char *) (addr) + i * entry_slot_len + type_offset) = 0x01;
    for (int i = 0; i < pdr_round; i++) {
        for (int j = 0; j < entry_num; j++) *((char *) (addr) + (i + 1) * entry_num * entry_slot_len + j * entry_slot_len + type_offset) = 0x02;
    }*/
    printf("ue pdr inited.\n");
}

int Server::init() {
    struct ibv_device *dev = IBNetworking::getInstance().getDeviceByName(this->device);
    if (!dev) {
        this->logger->error("Unable to get device {0}, aborting.", this->device);
        return 1;
    }
    std::string iface = IBNetworking::getInstance().getDeviceNetDevice(dev);
    if (iface.empty()) {
        this->logger->info("Net device not found, aborting.");
        return 1;
    }

    this->connection = ConnectionManager::getInstance().create(dev);

    this->logger->info("p1");

    
    std::pair<uint8_t, struct ibv_port_attr *> *portInfo = IBNetworking::getInstance().getDevicePort(
            this->connection->ibCtx, dev
    );
    
    //std::pair<uint8_t, struct ibv_port_attr *> *portInfo = NULL;

    printf("p2\n");
    this->logger->info("p2");

    if (portInfo->second->state != IBV_PORT_ACTIVE) {
        /* Port is not active, return */
        this->logger->error("Device {0} is not active, aborting.", this->device);
        return 1;
    }

   this->logger->info("p3");

    struct ibv_gid_entry *gidEntry = IBNetworking::getInstance().getDeviceGid(this->connection->ibCtx, dev, portInfo);
    if (!gidEntry) {
        /* We only match IPv4 addresses for GID entry */
        this->logger->error("Unable to get GID entry for device {0}, aborting.", this->device);
        return 1;
    }

    this->logger->info("p4");

    /* Since when creating the QP it tries to resolve the IP address by doing an ARP request, we put a fake
     * ARP entry to the client IP address to avoid errors */
    IBNetworking::getInstance().addFakeARPEntry(htobe32(RDMA_IP), iface);

    /* Create a fake client GID, putting as IP the fake client IP Addr */
    auto *clientGid = new union ibv_gid;
    std::memcpy(clientGid, gidEntry, sizeof(union ibv_gid));
    clientGid->raw[12] = (RDMA_IP & 0xff000000) >> 24;
    clientGid->raw[13] = (RDMA_IP & 0x00ff0000) >> 16;
    clientGid->raw[14] = (RDMA_IP & 0x0000ff00) >> 8;
    clientGid->raw[15] = RDMA_IP & 0x000000ff;

    this->qpAttrs = new struct ibv_qp_attr;
    memset(this->qpAttrs, 0, sizeof(struct ibv_qp_attr));
    this->qpAttrs->port_num = portInfo->first;
    this->qpAttrs->qp_access_flags = IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ;
    this->qpAttrs->ah_attr.port_num = portInfo->first;
    this->qpAttrs->ah_attr.grh = (struct ibv_global_route) {
            .dgid = *clientGid,
            .flow_label = 0x0,
            .sgid_index = (uint8_t) gidEntry->gid_index,
            .hop_limit = 64,
            .traffic_class = 0x0
    };
    this->qpAttrs->ah_attr.is_global = 1;


    this->logger->info("arp set, creating QP");
    /* Create QPs */
    std::random_device rd;
    std::mt19937_64 mt(rd());
    std::uniform_int_distribution<uint16_t> distribution(this->minDistrValue, this->maxDistrValue);
    for (uint16_t qpIdx = 0; qpIdx < this->qps; qpIdx++) {
        auto *qp = ConnectionManager::getInstance().createQueuePair(connection, this->qpAttrs);

        uint16_t uniqueServerQpIdx = qpIdx + (this->qps * this->idx);

        ConnectionManager::getInstance().connectQueuePair(
                connection, qp->qp_num, uniqueServerQpIdx, ibv_mtu::IBV_MTU_4096, this->qpAttrs
        );
        connection->idxToDestQp->insert(std::pair<uint32_t, uint32_t>(uniqueServerQpIdx, qp->qp_num));
        connection->idxToResetting->insert(std::pair<uint32_t, bool>(uniqueServerQpIdx, false));
        this->logger->info(
                "Sending QP with IDX={0}, DEST_QP_NUM={1:x} information to switch...", uniqueServerQpIdx, qp->qp_num
        );
        std::pair<uint8_t *, std::size_t> *request = Serializer::serializeRDMAQPInfo(
                distribution(mt), uniqueServerQpIdx, qp->qp_num
        );
        this->crafter->sendRDMAInfoPacket(request->first, request->second, iface);
        delete (request);
    }

    delete (portInfo);
    delete (gidEntry);
    delete (clientGid);

    this->logger->info("Prepare memory");

    /* Allocate Memory Region */
    ibv_mr *memoryRegion = BufferManager::getInstance().create(
            connection, PAYLOAD_BUFFER_SIZE, this->numaNode,
            IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_READ
    );
    std::pair<uint8_t *, std::size_t> *request = Serializer::serializeRDMAMemInfo(
            this->idx, (uintptr_t) memoryRegion->addr, memoryRegion->rkey
    );
    this->crafter->sendRDMAInfoPacket(request->first, request->second, iface);
    delete (request);

    /* Send Eth Info */
    uint64_t macAddress = IBNetworking::getInstance().getDeviceMacAddress(dev);
    uint32_t ipAddress = IBNetworking::getInstance().getDeviceIpAddress(dev);
    request = Serializer::serializeRDMAEthInfo(this->idx, macAddress, ipAddress);
    this->crafter->sendRDMAInfoPacket(request->first, request->second, iface);
    delete (request);

    /* Init Socket Connection Thread */
    connection->socketConnectionThread = new std::thread(
            &SocketConnection::init, connection, this->qpAttrs, this->crafter, iface,
            this->minDistrValue, this->maxDistrValue
    );
    connection->socketConnectionThread->detach();

    init_ue_pdr((uintptr_t) memoryRegion->addr);
    connection->dispThread = new std::thread(&(Server::disp_mem), (uintptr_t) memoryRegion->addr);
    connection->dispThread->detach();

    return 0;
}

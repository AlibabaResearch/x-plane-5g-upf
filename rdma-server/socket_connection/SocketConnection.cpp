#include "SocketConnection.h"

SocketConnection::SocketConnection(boost::asio::io_service &ioService, Connection *connection,
                                   struct ibv_qp_attr *qpAttrs, std::shared_ptr<PacketCrafter> crafter,
                                   const std::string &iface, uint16_t minDistrValue, uint16_t maxDistrValue) :
        socket(ioService, raw_protocol_t(PF_PACKET, SOCK_RAW)) {
    try {
        this->logger = spdlog::stdout_logger_mt("SocketConnection");
    } catch (spdlog::spdlog_ex &ex) {
        spdlog::drop("SocketConnection");

        this->logger = spdlog::stdout_logger_mt("SocketConnection");
    }

    this->connection = connection;
    this->qpAttrs = qpAttrs;
    this->crafter = std::move(crafter);
    this->iface = iface;

    std::random_device rd;
    this->mt = std::mt19937_64(rd());
    this->distribution = std::uniform_int_distribution<uint16_t>(minDistrValue, maxDistrValue);

    auto *sockaddr = new sockaddr_ll;
    memset(sockaddr, 0, sizeof(sockaddr_ll));
    sockaddr->sll_family = PF_PACKET;
    sockaddr->sll_protocol = htons(ETH_P_ALL);
    sockaddr->sll_hatype = 1;
    sockaddr->sll_ifindex = if_nametoindex(this->iface.c_str());
    raw_endpoint_t endpoint(sockaddr, sizeof(sockaddr_ll));
    delete (sockaddr);

    this->socket.bind(endpoint);

    this->startReceive();
}

void SocketConnection::init(Connection *connection, struct ibv_qp_attr *qpAttrs, std::shared_ptr<PacketCrafter> crafter,
                            const std::string &iface, uint16_t minDistrValue, uint16_t maxDistrValue) {
    boost::asio::io_service ioContext;

    SocketConnection socket(ioContext, connection, qpAttrs, std::move(crafter),
                            iface, minDistrValue, maxDistrValue);

    ioContext.run();
}

void SocketConnection::startReceive() {
    raw_endpoint_t remoteEndpoint;
    this->socket.async_receive_from(
            boost::asio::buffer(this->buffer), remoteEndpoint,
            boost::bind(
                    &SocketConnection::onMessage, this, boost::asio::placeholders::error,
                    boost::asio::placeholders::bytes_transferred
            )
    );
}

void SocketConnection::onMessage(const boost::system::error_code &error, std::size_t bytesTransferred) {
    this->startReceive();

    if (!error) {
        auto *ptr = this->buffer.data();
        if (ptr[12] == 0x43 && ptr[13] == 0x21) {
            /* client_qp_refresh packet */
            /* Skip Ethernet header (14 bytes) */
            ptr = ptr + 14;

            /* Parse data */
            uint16_t idx;
            std::memcpy(&idx, ptr, sizeof(uint16_t));
            idx = be16toh(idx);

            this->logger->info("client_qp_refresh - IDX = {0}", idx);

            this->resetQueuePair(idx);
        }
    }
}

void SocketConnection::resetQueuePair(uint16_t idx) {
    auto it = connection->idxToResetting->find(idx);

    if (it != connection->idxToResetting->end() && !it->second) {
        it->second = true;

        uint32_t serverQp = this->connection->idxToDestQp->at(idx);
        auto *qp = connection->queuePairs->at(serverQp);

        /* Since when creating the QP it tries to resolve the IP address by doing an ARP request, we put a fake
         * ARP entry to the client IP address to avoid errors */
        IBNetworking::getInstance().addFakeARPEntry(htobe32(RDMA_IP), this->iface);

        ConnectionManager::getInstance().resetQueuePair(qp, this->qpAttrs);
        ConnectionManager::getInstance().connectQueuePair(
                connection, qp->qp_num, idx, ibv_mtu::IBV_MTU_4096, this->qpAttrs
        );

        std::pair<uint8_t *, std::size_t> *request = Serializer::serializeRDMAQPInfo(
                this->distribution(this->mt), idx, qp->qp_num
        );
        this->crafter->sendRDMAInfoPacket(request->first, request->second, this->iface);
        delete (request);

        it->second = false;
    }
}
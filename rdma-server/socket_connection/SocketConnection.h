#ifndef RDMA_SERVER_SOCKETCONNECTION_H
#define RDMA_SERVER_SOCKETCONNECTION_H

#include "../common/common.h"
#include "../connection_manager/Connection.h"
#include "../connection_manager/ConnectionManager.h"
#include "../packet_crafter/PacketCrafter.h"
#include "../serializer/Serializer.h"
#include "../ib_networking/IBNetworking.h"

#include <random>
#include <utility>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <boost/asio.hpp>
#include <boost/array.hpp>
#include <boost/system/error_code.hpp>
#include <boost/bind/bind.hpp>

class SocketConnection {
public:
    SocketConnection(boost::asio::io_service &, Connection *, struct ibv_qp_attr *, std::shared_ptr<PacketCrafter>,
            const std::string &, uint16_t, uint16_t);

    void startReceive();

    void onMessage(const boost::system::error_code &, std::size_t);

    void resetQueuePair(uint16_t);

    static void init(Connection *, struct ibv_qp_attr *, std::shared_ptr<PacketCrafter>, const std::string &, uint16_t, uint16_t);

    typedef boost::asio::generic::raw_protocol raw_protocol_t;
    typedef boost::asio::generic::basic_endpoint<raw_protocol_t> raw_endpoint_t;

private:
    std::shared_ptr<spdlog::logger> logger = nullptr;

    Connection *connection = nullptr;
    struct ibv_qp_attr *qpAttrs = nullptr;
    std::shared_ptr<PacketCrafter> crafter = nullptr;
    std::string iface;

    raw_protocol_t::socket socket;
    std::array<uint8_t, 65536> buffer{};

    std::mt19937_64 mt;
    std::uniform_int_distribution<uint16_t> distribution;
};

#endif
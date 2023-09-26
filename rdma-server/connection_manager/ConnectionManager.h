#ifndef RDMA_SERVER_CONNECTIONMANAGER_H
#define RDMA_SERVER_CONNECTIONMANAGER_H

#pragma once

#include "../common/common.h"
#include "../queue_manager/QueueManager.h"
#include "../buffer_manager/BufferManager.h"
#include "./Connection.h"

class ConnectionManager {
public:
    static ConnectionManager &getInstance();

    ConnectionManager(ConnectionManager const &) = delete;

    void operator=(ConnectionManager const &) = delete;

    ~ConnectionManager();

    Connection *create(struct ibv_device *);

    void destroy(Connection *);

    struct ibv_qp *createQueuePair(Connection *, struct ibv_qp_attr *);

    void connectQueuePair(Connection *, uint32_t, uint32_t, ibv_mtu, struct ibv_qp_attr *);

    void resetQueuePair(struct ibv_qp *, struct ibv_qp_attr *);

private:
    ConnectionManager();

    std::shared_ptr<spdlog::logger> logger = nullptr;

    std::shared_ptr<QueueManager> queueManager = std::make_shared<QueueManager>();

    std::mutex queuePairsMtx;
};

#endif

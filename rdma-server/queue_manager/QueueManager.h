#ifndef RDMA_SERVER_QUEUEMANAGER_H
#define RDMA_SERVER_QUEUEMANAGER_H

#pragma once

#include "common/common.h"
#include "connection_manager/Connection.h"

class QueueManager {
public:
    QueueManager();

    ~QueueManager();

    struct ibv_qp *createQueuePair(Connection *, uint32_t, uint32_t, uint32_t, uint32_t);

    void destroyQueuePair(struct ibv_qp *);

    void transitionToReset(struct ibv_qp *);

    void transitionToInit(struct ibv_qp *, uint8_t, uint);

    void transitionToRTR(struct ibv_qp *, ibv_mtu, uint32_t, struct ibv_ah_attr);

    void transitionToRTS(struct ibv_qp *);

    void createCompletionQueue(Connection *, int);

    void destroyCompletionQueue(Connection *);
private:
    std::shared_ptr<spdlog::logger> logger = nullptr;
};

#endif

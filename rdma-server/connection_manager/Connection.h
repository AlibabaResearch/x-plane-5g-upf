#ifndef RDMA_SERVER_CONNECTION_H
#define RDMA_SERVER_CONNECTION_H

#pragma once

#include <map>

typedef struct {
    struct ibv_context *ibCtx;
    struct ibv_pd *protectionDomain;
    struct ibv_cq *completionQueue;
    struct ibv_comp_channel *completionChannel;

    std::thread *socketConnectionThread;
     std::thread *dispThread;

    std::map<uint32_t, struct ibv_qp *> *queuePairs;
    std::map<uint32_t, uint32_t> *idxToDestQp;
    std::map<uint32_t, bool> *idxToResetting;
} Connection;

#endif
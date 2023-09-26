#include "QueueManager.h"

QueueManager::QueueManager() {
    this->logger = spdlog::stdout_logger_mt("QueueManager");
}

QueueManager::~QueueManager() {
    this->logger.reset();

    spdlog::drop("QueueManager");
}

struct ibv_qp *QueueManager::createQueuePair(Connection *connection, uint32_t maxSendWr, uint32_t maxRecvWr,
                                             uint32_t maxSendSge, uint32_t maxRecvSge) {
    this->logger->info("Creating QP with maxSendWr={0}, maxRecvWr={1}, maxSendSge={2}, maxRecvSge={3}...",
                       maxSendWr, maxRecvWr, maxSendSge, maxRecvSge);

    auto *queuePairAttributes = new struct ibv_qp_init_attr;
    memset(queuePairAttributes, 0, sizeof(struct ibv_qp_init_attr));

    queuePairAttributes->send_cq = connection->completionQueue;
    queuePairAttributes->recv_cq = connection->completionQueue;
    queuePairAttributes->qp_type = IBV_QPT_RC;
    queuePairAttributes->cap.max_send_wr = maxSendWr;
    queuePairAttributes->cap.max_recv_wr = maxRecvWr;
    queuePairAttributes->cap.max_send_sge = maxSendSge;
    queuePairAttributes->cap.max_recv_sge = maxRecvSge;

    struct ibv_qp *qp = ibv_create_qp(connection->protectionDomain, queuePairAttributes);
    delete (queuePairAttributes);

    if (!qp) {
        this->logger->error("Failed to create QP: {0}", strerror(errno));
        return nullptr;
    }

    this->logger->info("QP created successfully with QP Num = {0:x}!", qp->qp_num);

    return qp;
}

void QueueManager::transitionToReset(struct ibv_qp *qp) {
    this->logger->info("Moving QP = {0:x} into RESET state...", qp->qp_num);

    auto *initAttrs = new struct ibv_qp_attr;
    memset(initAttrs, 0, sizeof(struct ibv_qp_attr));
    initAttrs->qp_state = ibv_qp_state::IBV_QPS_RESET;

    if (ibv_modify_qp(qp, initAttrs, IBV_QP_STATE))
        this->logger->error("Failed to modify QP to RESET: {0}", strerror(errno));

    delete (initAttrs);
}

void QueueManager::transitionToInit(struct ibv_qp *qp, uint8_t portNum, uint accessFlags) {
    this->logger->info("Moving QP = {0:x} into INIT state...", qp->qp_num);

    auto *initAttrs = new struct ibv_qp_attr;
    memset(initAttrs, 0, sizeof(struct ibv_qp_attr));
    initAttrs->qp_state = ibv_qp_state::IBV_QPS_INIT;
    initAttrs->port_num = portNum;
    initAttrs->pkey_index = 0;
    initAttrs->qp_access_flags = accessFlags;

    if (ibv_modify_qp(qp, initAttrs, IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS))
        this->logger->error("Failed to modify QP to INIT: {0}", strerror(errno));

    delete (initAttrs);
}

void QueueManager::transitionToRTR(struct ibv_qp *qp, ibv_mtu mtu, uint32_t destQp, struct ibv_ah_attr attrs) {
    this->logger->info("Moving QP = {0:x} into RTR state...", qp->qp_num);

    auto *rtrAttrs = new struct ibv_qp_attr;
    memset(rtrAttrs, 0, sizeof(struct ibv_qp_attr));
    rtrAttrs->qp_state = ibv_qp_state::IBV_QPS_RTR;
    rtrAttrs->path_mtu = mtu;
    rtrAttrs->dest_qp_num = destQp;
    rtrAttrs->rq_psn = 0;
    rtrAttrs->max_dest_rd_atomic = MAX_RD_ATOMIC;
    rtrAttrs->min_rnr_timer = 0;
    rtrAttrs->ah_attr = attrs;

    if (ibv_modify_qp(qp, rtrAttrs,
                      IBV_QP_STATE | IBV_QP_PATH_MTU | IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
                      IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER | IBV_QP_AV))
        this->logger->error("Failed to modify QP to RTR: {0}", strerror(errno));

    delete (rtrAttrs);
}

void QueueManager::transitionToRTS(struct ibv_qp *qp) {
    this->logger->info("Moving QP = {0:x} into RTS state...", qp->qp_num);

    auto *rtsAttrs = new struct ibv_qp_attr;
    memset(rtsAttrs, 0, sizeof(struct ibv_qp_attr));
    rtsAttrs->qp_state = ibv_qp_state::IBV_QPS_RTS;
    rtsAttrs->timeout = 0;
    rtsAttrs->retry_cnt = RNR_RETRY;
    rtsAttrs->rnr_retry = RNR_RETRY;
    rtsAttrs->sq_psn = 0;
    rtsAttrs->max_rd_atomic = MAX_RD_ATOMIC;

    if (ibv_modify_qp(qp, rtsAttrs,
                      IBV_QP_STATE | IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT | IBV_QP_RNR_RETRY |
                      IBV_QP_SQ_PSN | IBV_QP_MAX_QP_RD_ATOMIC))
        this->logger->error("Failed to modify QP to RTS: {0}", strerror(errno));

    delete (rtsAttrs);
}

void QueueManager::destroyQueuePair(struct ibv_qp *qp) {
    this->logger->info("Destroying Queue Pair with QP Num = {0:x}", qp->qp_num);

    ibv_destroy_qp(qp);
}

void QueueManager::createCompletionQueue(Connection *connection, int cqEntries) {
    this->logger->info("Creating Completion Channel...");
    connection->completionChannel = ibv_create_comp_channel(connection->ibCtx);
    this->logger->info("Completion Channel created!");

    this->logger->info("Creating Completion Queue...");
    connection->completionQueue = ibv_create_cq(connection->ibCtx, cqEntries, nullptr,
                                                connection->completionChannel, 0);
}

void QueueManager::destroyCompletionQueue(Connection *connection) {
    ibv_destroy_comp_channel(connection->completionChannel);
}
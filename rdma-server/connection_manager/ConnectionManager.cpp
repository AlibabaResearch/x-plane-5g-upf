#include "ConnectionManager.h"

ConnectionManager::ConnectionManager() {
    this->logger = spdlog::stdout_logger_mt("ConnectionManager");
}

ConnectionManager::~ConnectionManager() {
    this->logger.reset();
    this->queueManager.reset();

    spdlog::drop("ConnectionManager");
}

ConnectionManager &ConnectionManager::getInstance() {
    static ConnectionManager instance;
    return instance;
}

Connection *ConnectionManager::create(struct ibv_device *device) {
    auto *connection = new Connection;
    connection->ibCtx = ibv_open_device(device);

    this->logger->info("Allocating Protection Domain...");
    connection->protectionDomain = ibv_alloc_pd(connection->ibCtx);

    this->queueManager->createCompletionQueue(connection, 10);

    connection->queuePairs = new std::map<uint32_t, struct ibv_qp *>;
    connection->idxToDestQp = new std::map<uint32_t, uint32_t>();
    connection->idxToResetting = new std::map<uint32_t, bool>();

    return connection;
}

void ConnectionManager::destroy(Connection *connection) {
    for (auto const &qp: *connection->queuePairs) {
        this->queueManager->destroyQueuePair(qp.second);
    }
    delete (connection->queuePairs);
    delete (connection->idxToDestQp);
    delete (connection->idxToResetting);

    this->queueManager->destroyCompletionQueue(connection);

    ibv_dealloc_pd(connection->protectionDomain);

    ibv_close_device(connection->ibCtx);

    delete (connection);
}

struct ibv_qp *ConnectionManager::createQueuePair(Connection *connection, struct ibv_qp_attr *attr) {
    struct ibv_qp *qp = this->queueManager->createQueuePair(connection, MAX_WR, MAX_WR, MAX_SGE, MAX_SGE);
    if (qp) {
        this->queuePairsMtx.lock();
        connection->queuePairs->insert(std::pair<uint32_t, struct ibv_qp *>(qp->qp_num, qp));
        this->queuePairsMtx.unlock();

        this->queueManager->transitionToInit(qp, attr->port_num, attr->qp_access_flags);

        return qp;
    }

    return nullptr;
}

void ConnectionManager::connectQueuePair(Connection *connection, uint32_t qpNum, uint32_t destQpNum, ibv_mtu mtu,
                                         struct ibv_qp_attr *attr) {
    this->logger->info("Connecting QP with QP Num = {0:x} to QP = {1:x}", qpNum, destQpNum);

    struct ibv_qp *qp = connection->queuePairs->at(qpNum);

    this->queueManager->transitionToRTR(qp, mtu, destQpNum, attr->ah_attr);
    this->queueManager->transitionToRTS(qp);
}

void ConnectionManager::resetQueuePair(struct ibv_qp *qp, struct ibv_qp_attr *attr) {
    this->logger->info("Resetting QP with QP Num = {0:x}", qp->qp_num);

    this->queueManager->transitionToReset(qp);
    this->queueManager->transitionToInit(qp, attr->port_num, attr->qp_access_flags);
}
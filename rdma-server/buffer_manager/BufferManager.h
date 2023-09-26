#ifndef RDMA_SERVER_BUFFERMANAGER_H
#define RDMA_SERVER_BUFFERMANAGER_H

#include <map>
#include <numa.h>
#include "common/common.h"
#include "connection_manager/Connection.h"


class BufferManager {
public:
    static BufferManager &getInstance();

    BufferManager(BufferManager const &) = delete;

    void operator=(BufferManager const &) = delete;

    ~BufferManager();

    ibv_mr *create(Connection *, uint64_t, uint16_t, int, std::string = "");

    ibv_mr *get(Connection *, const std::string &);

    void destroy(Connection *, uint16_t);

private:
    BufferManager();

    std::shared_ptr<spdlog::logger> logger = nullptr;

    std::unique_ptr<std::map<Connection *, std::map<std::string, ibv_mr *> *>> id2MemoryRegions;
};

#endif

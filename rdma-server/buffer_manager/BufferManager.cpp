#include "BufferManager.h"
#include <memory>

BufferManager::BufferManager() {
    this->logger = spdlog::stdout_logger_mt("BufferManager");

    this->id2MemoryRegions = std::make_unique<std::map<Connection *, std::map<std::string, ibv_mr *> *>>();
}

BufferManager::~BufferManager() {
    auto *ptr = this->id2MemoryRegions.release();
    delete (ptr);

    spdlog::drop("BufferManager");
}

BufferManager &BufferManager::getInstance() {
    static BufferManager instance;
    return instance;
}

ibv_mr *BufferManager::create(Connection *connection, uint64_t length, uint16_t numaNode,
                              int access, std::string name) {
    if (name.empty()) {
        const auto clock = std::chrono::system_clock::now();
        const auto key = std::chrono::duration_cast<std::chrono::seconds>(clock.time_since_epoch()).count();
        name = std::to_string(key);
    }

    this->logger->info("Registering buffer with name `{0}` and length {1}...", name, length);

    void *region = numa_alloc_onnode(length, numaNode);
    ibv_mr *memoryRegion = ibv_reg_mr(connection->protectionDomain, region, length, access);

    auto ret = this->id2MemoryRegions->insert(
            std::pair<Connection *, std::map<std::string, ibv_mr *> *>(
                    connection,
                    new std::map<std::string, ibv_mr *>()
            )
    );

    ret.first->second->insert(std::pair<std::string, ibv_mr *>(name, memoryRegion));

    return memoryRegion;
}

ibv_mr *BufferManager::get(Connection *connection, const std::string &name) {
    auto it = this->id2MemoryRegions->find(connection);
    if (it == this->id2MemoryRegions->end())
        return nullptr;

    auto value = it->second->find(name);
    if (value == it->second->end())
        return nullptr;

    return value->second;
}

void BufferManager::destroy(Connection *connection, uint16_t numaNode) {
    auto it = this->id2MemoryRegions->find(connection);
    if (it == this->id2MemoryRegions->end())
        return;

    for (auto &values: *it->second) {
        ibv_mr *memoryRegion = values.second;

        numa_free(memoryRegion->addr, numaNode);

        ibv_dereg_mr(memoryRegion);
    }

    delete (it->second);

    id2MemoryRegions->erase(connection);
}

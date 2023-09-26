#include "server/Server.h"

volatile sig_atomic_t flag;

void handler(int) {
    flag = 1;
}

int main(int argc, char **argv) {
    if (argc != 7) {
        std::cout << "Usage: server <device> <idx> <numa> <qps> <min-timer> <max-timer>" << std::endl;
        std::cout << "\t<device>: name of the device to use for the connection (example: mlx5_1)" << std::endl;
        std::cout << "\t<idx>: unique index associated to this server (starting from 0)" << std::endl;
        std::cout << "\t<numa>: index of the NUMA node to use when allocating buffers" << std::endl;
        std::cout << "\t<qps>: number of Queue-Pairs to create" << std::endl;
        std::cout << "\t<min-timer>: minimum QP reset timer value, in number of packets (example: 200)" << std::endl;
        std::cout << "\t<max-timer>: maximum QP reset timer value, in number of packets (example: 2000)" << std::endl;

        return 1;
    }

    signal(SIGINT, &handler);

    Server *server = nullptr;
    try {
        server = new Server(std::string(argv[1]), std::stoi(argv[2]),
                            std::stoi(argv[3]), std::stoi(argv[4]),
                            std::stoi(argv[5]), std::stoi(argv[6]));
        if (server->init() == 0) {
            for (;;) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1000));
                if (flag) throw (int) flag;
            
        }
    }} catch (int x) {
        delete (server);
    }

    return 0;
}


# Ribosome-RDMA-Server-Agent
This repository contains the code needed to run the RDMA server agent in the Ribosome system. 

## Requirements
The agent is designed to run on a server equipped with a [Mellanox ConnectX-5](https://www.nvidia.com/en-us/networking/ethernet/connectx-5/) NIC.

Before compiling the agent you need to install the following libraries: 
- [spdlog](https://github.com/gabime/spdlog)
- [libcrafter](https://github.com/pellegre/libcrafter)
- [Boost System](https://www.boost.org/doc/libs/1_68_0/libs/system/doc/index.html)

Before running the server agent, you need to disable the iCRC check on the specific ConnectX-5 port.
In this repository, such commands are not shown as they are under NDA.

## How To Compile
In order to compile the agent, run the following commands:
```bash
mkdir build && cd build
cmake -S .. -B . && make -j
```

## Usage
```
server <device> <idx> <numa> <qps> <min-timer> <max-timer>
```

- `<device>`: name of the device to use for the connection with Ribosome switch (example: `mlx5_1`)
- `<idx>`: unique index associated to this server, starting from 0. Each RDMA Agent process should be identified with a different index, assigned sequentially
- `<numa>`: index of the NUMA node to use when allocating buffers
- `<qps>`: number of Queue-Pairs to create
- `<min-timer>`: minimum QP reset timer value, in number of packets (example: 200). This is used (in conjuction with `<max-timer>`) to compute a random value that is used in the Ribosome Tofino to idle sending packets towards a freshly restored QP
- `<max-timer>`: maximum QP reset timer value, in number of packets (example: 2000). This is used (in conjuction with `<min-timer>`) to compute a random value that is used in the Ribosome Tofino to idle sending packets towards a freshly restored QP
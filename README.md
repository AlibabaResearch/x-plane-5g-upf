# X-Plane-5g-UPF
### Tofino
#### Compilation

- Kernel: Linux 4.14.151-OpenNetworkLinux
- SDE: bf-sde-9.7.1
```
bf-p4c -g --archive --verbose 2 --std p4-16 --target tofino --arch tna --arch tna --Wdisable unused -Xp4c="--auto-init-metadata" --bf-rt-schema bf-rt.json --Wdisable type-error -DSPLIT=128 -o main-fix1 main-fix1.p4
```
#### Installation
```
cp -r main-fix1.tofino/ $SDE_INSTALL/
```
#### Run
```
cd $SDE_INSTALL/
$SDE/run_switchd.sh -p main-fix1 -c main-fix1.tofino/main-fix1.conf
$SDE/run_bfshell.sh -f init_cfg 
```
### RDMA server
#### Compilation

1. spdlog
```bash
git clone https://github.com/gabime/spdlog.git
cd spdlog && mkdir build && cd build 
cmake .. && make -j && make install
```

2. libcrafter
```bash
yum install libpcap-devel
./autogen
./configure
make
make install
cp crafter.pc [PKG_CONFIG_PATH]
```

3. boost
```bash
yum install boost
yum install boost-devel
```

4. build the server
```bash
mkdir build && cd build
cmake -S .. -B . && make -j
```
#### Run
```
./server mlx5_0 0 1 32 100 2000
```
### Traffic generator 
#### Setup

- DPDK 21.11.1
- Trex v3.00
#### Run
```
cd /root/trex.v3.00
./t-rex-64 -c 20 -i
./trex-console
```


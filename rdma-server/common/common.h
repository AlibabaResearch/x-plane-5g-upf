#ifndef RDMA_SERVER_COMMON_H
#define RDMA_SERVER_COMMON_H

#pragma once

#include <iostream>
#include <thread>
#include <spdlog/spdlog.h>
#include <chrono>
#include <spdlog/sinks/stdout_sinks.h>
#include <infiniband/verbs.h>
#include <memory>

/* 4.5GB  - changed to 16 GB*/
#define PAYLOAD_BUFFER_SIZE 0x400000000 //0x120000000
/* Constant Parameters */
#define MAX_WR 8192
#define MAX_SGE 1
#define MAX_RD_ATOMIC 16
#define RNR_RETRY 7
/* Fake RDMA IP Address */
#define RDMA_IP 0xc0a828fe

#endif

#cmake_minimum_required(VERSION 3.10)
cmake_minimum_required(VERSION 3.6)
project(rdma_server C CXX)
include(FindPkgConfig)

set(CMAKE_CXX_STANDARD 14)

set(CMAKE_CXX_FLAGS   "-g")

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${PROJECT_SOURCE_DIR}/")

pkg_search_module(LIBCRAFTER REQUIRED crafter)
pkg_search_module(SPDLOG REQUIRED spdlog)

include_directories(. ./common)

add_library(server-lib STATIC
        common/common.h
        connection_manager/Connection.h
        ib_networking/IBNetworking.h ib_networking/IBNetworking.cpp
        buffer_manager/BufferManager.h buffer_manager/BufferManager.cpp
        queue_manager/QueueManager.h queue_manager/QueueManager.cpp
        connection_manager/ConnectionManager.h connection_manager/ConnectionManager.cpp
        serializer/Serializer.h serializer/Serializer.cpp
        packet_crafter/PacketCrafter.h packet_crafter/PacketCrafter.cpp
        socket_connection/SocketConnection.h socket_connection/SocketConnection.cpp
        server/Server.h server/Server.cpp
        )
target_link_libraries(server-lib ibverbs pthread boost_system numa ${SPDLOG_LIBRARIES} ${LIBCRAFTER_LIBRARIES})

add_executable(server server.cpp)
target_link_libraries(server server-lib)

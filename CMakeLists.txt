cmake_minimum_required(VERSION 3.17)
project(bindiff_server)

set(CMAKE_CXX_STANDARD 17)

set(gRPC_DIR "$HOME/.local")

find_package(protobuf REQUIRED)
find_package(gRPC REQUIRED)

include_directories(${Protobuf_INCLUDE_DIRS})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/build/generated)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/Server)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/SHA_256)

add_library(sha256 STATIC
		SHA_256/sha256.c
		SHA_256/sha256Wrapper.cpp
)
target_include_directories(sha256 PUBLIC
		${CMAKE_CURRENT_SOURCE_DIR}/SHA_256
)

add_executable(server
		Server/server_main.cpp

		build/generated/binexport2.pb.cc
		build/generated/bin_diff.pb.cc
		build/generated/bin_diff.grpc.pb.cc

		Server/BinDiffServer.cpp
		Server/BinDiffCache.cpp
		Server/BinExportContent.cpp
)
target_link_libraries(server
		gRPC::grpc++
		${Protobuf_LIBRARIES}
		sha256
)

add_executable(client
		Client/client_main.cpp

		build/generated/bin_diff.pb.cc
		build/generated/bin_diff.grpc.pb.cc
)
target_link_libraries(client
		gRPC::grpc++
		${Protobuf_LIBRARIES}
)
cmake_minimum_required(VERSION 3.17)
project(bindiff_server)

set(CMAKE_CXX_STANDARD 17)

set(gRPC_DIR "$HOME/.local")
set(SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src")

find_package(protobuf REQUIRED)
find_package(gRPC REQUIRED)

include_directories(${Protobuf_INCLUDE_DIRS})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${SRC_DIR})
include_directories(${SRC_DIR}/build/generated)
include_directories(${SRC_DIR}/Server)
include_directories(${SRC_DIR}/Server/MatchingAlgorithms)
include_directories(${SRC_DIR}/SHA_256)

add_library(sha256 STATIC
		${SRC_DIR}/SHA_256/sha256.c
		${SRC_DIR}/SHA_256/sha256Wrapper.cpp
)
target_include_directories(sha256 PUBLIC
		${SRC_DIR}/SHA_256
)

add_executable(server
		${SRC_DIR}/Server/server_main.cpp

		${SRC_DIR}/build/generated/binexport2.pb.cc
		${SRC_DIR}/build/generated/bin_diff.pb.cc
		${SRC_DIR}/build/generated/bin_diff.grpc.pb.cc

		${SRC_DIR}/Server/BinDiffServer.cpp
		${SRC_DIR}/Server/BinDiffCache.cpp
		${SRC_DIR}/Server/BinExportContent.cpp

		${SRC_DIR}/Server/MatchingAlgorithms/MatchingAlgorithm.h
		${SRC_DIR}/Server/BinDiffEngine.cpp

		${SRC_DIR}/Server/MatchingAlgorithms/NameMatcher.cpp
		${SRC_DIR}/Server/MatchingAlgorithms/NameMatcher.h
)
target_link_libraries(server
		gRPC::grpc++
		${Protobuf_LIBRARIES}
		sha256
)

add_executable(client
		${SRC_DIR}/Client/client_main.cpp

		${SRC_DIR}/build/generated/bin_diff.pb.cc
		${SRC_DIR}/build/generated/bin_diff.grpc.pb.cc

		${SRC_DIR}/Client/BinDiffClient.cpp
)
target_link_libraries(client
		gRPC::grpc++
		${Protobuf_LIBRARIES}
)

add_subdirectory(test)

cmake_minimum_required(VERSION 3.17)
project(BinDiffTests)

enable_testing()

set(gRPC_DIR "$HOME/.local")
set(SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../src")

find_package(protobuf REQUIRED)
find_package(gRPC REQUIRED)
find_package(GTest REQUIRED)

include_directories(${Protobuf_INCLUDE_DIRS})
include_directories(${GTEST_INCLUDE_DIRS})
include_directories(${SRC_DIR}/Client)
include_directories(${SRC_DIR}/build/generated)

add_executable(test_upload_get
		test_upload_get.cpp

		${SRC_DIR}/build/generated/bin_diff.pb.cc
		${SRC_DIR}/build/generated/bin_diff.grpc.pb.cc

		${SRC_DIR}/Client/BinDiffClient.cpp
)
target_link_libraries(test_upload_get
		GTest::gtest_main
        gRPC::grpc++
        ${Protobuf_LIBRARIES}
)

include(GoogleTest)
gtest_discover_tests(test_upload_get)

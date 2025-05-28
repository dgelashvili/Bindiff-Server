cmake_minimum_required(VERSION 3.17)
project(BinDiffTests)

enable_testing()

find_package(protobuf REQUIRED)
find_package(gRPC REQUIRED)
find_package(GTest REQUIRED)

include_directories(${Protobuf_INCLUDE_DIRS})
include_directories(${GTEST_INCLUDE_DIRS})

add_executable(test_upload_get test_upload_get.cpp)
target_link_libraries(test_upload_get
        ${GTEST_LIBRARIES}
        pthread
        gRPC::grpc++
        ${Protobuf_LIBRARIES}
)

add_test(NAME UploadGetTest COMMAND test_upload_get)

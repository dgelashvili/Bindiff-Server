cmake_minimum_required(VERSION 3.17)
project(bindiff_server)

set(CMAKE_CXX_STANDARD 17)

set(gRPC_DIR "/home/demetre/grpc-install")

find_package(protobuf REQUIRED)
find_package(gRPC REQUIRED)

include_directories(${Protobuf_INCLUDE_DIRS})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/build/generated)

add_executable(server
		Server/server_main.cpp
		build/generated/helloworld.pb.cc
		build/generated/helloworld.grpc.pb.cc
)
target_link_libraries(server
		gRPC::grpc++
		${Protobuf_LIBRARIES}
)

add_executable(client
		Client/client_main.cpp
		build/generated/helloworld.pb.cc
		build/generated/helloworld.grpc.pb.cc
)
target_link_libraries(client
		gRPC::grpc++
		${Protobuf_LIBRARIES}
)

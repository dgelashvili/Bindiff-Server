cmake_minimum_required(VERSION 3.10)
project(bindiff_server)

set(CMAKE_CXX_STANDARD 17)

include_directories(${CMAKE_SOURCE_DIR})

add_library(Adder Adder.cpp)

add_executable(server Server/server_main.cpp)

add_executable(client Client/client_main.cpp)
target_link_libraries(client Adder)

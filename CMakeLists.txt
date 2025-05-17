cmake_minimum_required(VERSION 3.10)
project(bindiff_server)

set(CMAKE_CXX_STANDARD 17)


add_executable(bindiff_server main.cpp
        Adder.h
        Adder.cpp)

cmake_minimum_required(VERSION 3.10)
project(lab04)

set(CMAKE_CXX_STANDARD 17)

set(CMAKE_CXX_FLAGS "-lcrypto -Wall -pedantic")

add_executable(lab04 main.cpp)
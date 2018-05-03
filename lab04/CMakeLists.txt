cmake_minimum_required(VERSION 3.10)
project(lab04)

set(CMAKE_CXX_STANDARD 17)
link_libraries(crypto)
set(CMAKE_CXX_FLAGS " -Wall -pedantic")
    add_executable(lab04 main.cpp)
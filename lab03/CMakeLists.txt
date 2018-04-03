cmake_minimum_required(VERSION 3.9)
project(lab03)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -lcrypto -Wliteral-suffix")
set(CMAKE_C_STANDARD 99)

link_libraries(crypto)
add_executable(lab03 main.cpp)
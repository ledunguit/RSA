cmake_minimum_required(VERSION 3.28)
project(RSA)

set(CMAKE_CXX_STANDARD 17)
include_directories("include")
link_directories("lib")
link_libraries("libcryptopp.a")

add_executable(RSA RSA.cpp)
add_library(RSA_dll STATIC RSA.cpp)

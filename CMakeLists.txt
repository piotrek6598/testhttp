cmake_minimum_required(VERSION 3.16)
project(testhttp_raw C)

set(CMAKE_C_STANDARD 11)

add_executable(testhttp_raw testhttp_raw.c err.c)
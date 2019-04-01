cmake_minimum_required(VERSION 3.10)
project(bez C)

set(CMAKE_C_STANDARD 99)
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -W -Wall -Wextra -pedantic")

link_libraries(crypto)

add_executable(bez-1 homeworks/lab-2/ukol-1.c)
add_executable(bez-2 homeworks/lab-2/ukol-2.c)
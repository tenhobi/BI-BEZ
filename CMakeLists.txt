cmake_minimum_required(VERSION 3.10)
project(bez CXX C)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -W -Wall -Wextra -pedantic")

link_libraries(crypto)

#add_executable(task2-1 homeworks/lab-2/task1.c)
#add_executable(task2-2 homeworks/lab-2/task2.cpp)
add_executable(task3 homeworks/lab-3/task.cpp)

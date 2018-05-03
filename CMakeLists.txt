cmake_minimum_required(VERSION 3.9)
project(WiFiSniffer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -lpcap")

find_package(Threads REQUIRED)

add_executable(WiFiSniffer main.cpp ErrorCheckUtils.h TrafficAnalyzer.h Define.h Util.h MacAddress.h Communication.h)
target_link_libraries(WiFiSniffer ${CMAKE_THREAD_LIBS_INIT})
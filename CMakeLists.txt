cmake_minimum_required(VERSION 3.9)
project(WiFiSniffer)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -lpcap")

find_package(Threads REQUIRED)

file(GLOB SOURCE_FILES "src/*.h" "src/*.cpp")

add_executable(WiFiSniffer ${SOURCE_FILES})
target_link_libraries(WiFiSniffer ${CMAKE_THREAD_LIBS_INIT})
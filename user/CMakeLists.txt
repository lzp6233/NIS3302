cmake_policy(SET CMP0048 NEW)
project(ping VERSION 1.2)

cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

include(FetchContent)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

FetchContent_Declare(fmt
    GIT_REPOSITORY git@github.com:fmtlib/fmt.git
    GIT_TAG 10.1.1
)
FetchContent_Declare(docopt
    GIT_REPOSITORY git@github.com:docopt/docopt.cpp.git
    GIT_TAG v0.6.3
)

FetchContent_MakeAvailable(fmt)
FetchContent_MakeAvailable(docopt)

add_executable(portScan
    ICMP/network.cpp
    ICMP/ping.cpp
    port/PortScanner.cpp
    main.cpp
)

target_link_libraries(portScan
  PRIVATE
    fmt::fmt
    docopt
    net
    pcap
)

#target_compile_options(ping PRIVATE -fsanitize=address -g)
#target_link_options(ping PRIVATE -fsanitize=address)

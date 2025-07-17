## 设置CMake策略，允许使用project版本
cmake_policy(SET CMP0048 NEW)
project(ping VERSION 1.2)

## 指定CMake最低版本要求
cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

## 包含FetchContent模块，用于下载外部依赖
include(FetchContent)

## 设置C++标准为C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

## 声明fmt库的下载信息
FetchContent_Declare(fmt
    GIT_REPOSITORY git@github.com:fmtlib/fmt.git
    GIT_TAG 10.1.1
)
## 声明docopt库的下载信息
FetchContent_Declare(docopt
    GIT_REPOSITORY git@github.com:docopt/docopt.cpp.git
    GIT_TAG v0.6.3
)

## 使外部依赖库可用
FetchContent_MakeAvailable(fmt)
FetchContent_MakeAvailable(docopt)

## 添加可执行文件目标，命名为portScan
add_executable(portScan
    ICMP/network.cpp
    ICMP/ping.cpp
    port/PortScanner.cpp
    main.cpp
)

## 为可执行文件链接所需的库
target_link_libraries(portScan
  PRIVATE
    fmt::fmt    # 格式化输出库
    docopt      # 命令行参数解析库
    net         # 网络库
    pcap        # 数据包捕获库
)

## 已注释掉的地址消毒器选项，用于调试内存问题
#target_compile_options(ping PRIVATE -fsanitize=address -g)
#target_link_options(ping PRIVATE -fsanitize=address)

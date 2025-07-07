cmake_minimum_required(VERSION 3.14 FATAL_ERROR)  # 移到最前面
cmake_policy(SET CMP0048 NEW)
project(ping VERSION 1.2)

# 设置C++标准
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# 添加栈保护选项（解决-1073740791错误）
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-fstack-protector-strong)
    add_link_options(-fstack-protector-strong)
endif()

include(FetchContent)

# 修复依赖配置
# fmt - 添加关键编译选项
FetchContent_Declare(fmt
    GIT_REPOSITORY https://github.com/fmtlib/fmt.git  # 改为HTTPS协议
    GIT_TAG 10.1.1
    GIT_SHALLOW TRUE  # 加速克隆
    CMAKE_ARGS 
        -DFMT_TEST=OFF  # 禁用测试
        -DFMT_INSTALL=OFF  # 禁用安装
)

FetchContent_Declare(docopt
    GIT_REPOSITORY https://github.com/docopt/docopt.cpp.git
    GIT_TAG v0.6.3
    GIT_SHALLOW TRUE
)

FetchContent_Declare(httplib
    GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
    GIT_TAG v0.14.1
    GIT_SHALLOW TRUE
)

FetchContent_Declare(json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.2
    GIT_SHALLOW TRUE
)

# 使所有依赖可用 - 确保fmt先构建
FetchContent_MakeAvailable(fmt)  # 单独构建fmt
FetchContent_MakeAvailable(docopt httplib json)  # 然后构建其他

add_executable(portScan
    ICMP/network.cpp
    ICMP/ping.cpp
    port/PortScanner.cpp
    main.cpp
)

# 增强链接配置
target_link_libraries(portScan PRIVATE
    fmt::fmt
    docopt
    httplib::httplib  # 确保使用命名空间目标
    nlohmann_json::nlohmann_json
)

# 添加平台特定的网络库
if(WIN32)
    # Windows需要Winsock和IP帮助库
    target_link_libraries(portScan PRIVATE ws2_32 iphlpapi)
else()
    # Linux/macOS使用标准socket库
    target_link_libraries(portScan PRIVATE pthread)
endif()

# 改进pcap库查找
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

include_directories(${PCAP_INCLUDE_DIRS})
link_directories(${PCAP_LIBRARY_DIRS})
add_definitions(${PCAP_CFLAGS_OTHER})

target_link_libraries(portScan PRIVATE ${PCAP_LIBRARIES} net)

# 特殊处理Windows上的pcap路径
if(WIN32)
    # 确保能找到Npcap/WinPcap的头文件和库
    target_link_directories(portScan PRIVATE 
        "C:/Program Files/Npcap/Lib/x64"  # 默认安装路径
    )
    target_include_directories(portScan PRIVATE 
        "C:/Program Files/Npcap/Include"
    )
    # 链接Packet和wpcap库
    target_link_libraries(portScan PRIVATE Packet wpcap)
endif()
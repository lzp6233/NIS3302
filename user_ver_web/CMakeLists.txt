# 设置CMake最低版本要求
cmake_minimum_required(VERSION 3.14 FATAL_ERROR)  # 移到最前面
# 设置CMake策略，允许使用project版本
cmake_policy(SET CMP0048 NEW)
# 设置项目名称和版本
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

# 引入FetchContent模块，用于下载和构建外部依赖
include(FetchContent)

# 配置外部依赖库
# fmt - 格式化库
FetchContent_Declare(fmt
    GIT_REPOSITORY git@github.com:fmtlib/fmt.git  # 改为git协议
    GIT_TAG 10.1.1
    GIT_SHALLOW TRUE  # 加速克隆
    CMAKE_ARGS 
        -DFMT_TEST=OFF  # 禁用测试
        -DFMT_INSTALL=OFF  # 禁用安装
)

# docopt - 命令行参数解析库
FetchContent_Declare(docopt
    GIT_REPOSITORY git@github.com:docopt/docopt.cpp.git
    GIT_TAG v0.6.3
    GIT_SHALLOW TRUE
)

# httplib - C++ HTTP服务器库
FetchContent_Declare(httplib
    GIT_REPOSITORY git@github.com:yhirose/cpp-httplib.git
    GIT_TAG v0.14.1
    GIT_SHALLOW TRUE
)

# nlohmann/json - JSON处理库
FetchContent_Declare(json
    GIT_REPOSITORY git@github.com:nlohmann/json.git
    GIT_TAG v3.11.2
    GIT_SHALLOW TRUE
)

# 使所有依赖可用 - 确保fmt先构建
FetchContent_MakeAvailable(fmt)  # 单独构建fmt
FetchContent_MakeAvailable(docopt httplib json)  # 然后构建其他

# 定义主可执行文件及其源文件
add_executable(portScan
    ICMP/network.cpp
    ICMP/ping.cpp
    port/PortScanner.cpp
    main.cpp
)

# 链接依赖库
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

# 查找pcap包（用于原始数据包操作）
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

# 查找libnet库（用于创建原始数据包）
find_library(LIBNET_LIBRARY NAMES net libnet)
if(NOT LIBNET_LIBRARY)
    message(FATAL_ERROR "libnet library not found")
endif()

# 添加包含目录和链接目录
include_directories(${PCAP_INCLUDE_DIRS})
link_directories(${PCAP_LIBRARY_DIRS})
add_definitions(${PCAP_CFLAGS_OTHER})

# 链接pcap和net库
target_link_libraries(portScan PRIVATE ${PCAP_LIBRARIES} ${LIBNET_LIBRARY} net)

# Windows平台特殊处理
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
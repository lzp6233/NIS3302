# NIS3302 信息安全科技创新

本项目为信息安全科技创新课程的小组作业，旨在实现一个基础的入侵检测系统（IDS），用于检测和防御常见的网络入侵行为。

## 小组成员

- 刘梓芃 523031910639 liuzipeng@sjtu.edu.cn
- 聂鸣涛 523031910728 niemingtao@sjtu.edu.cn
- 李卓恒 523031910556 lzhsj32206@sjtu.edu.cn
- 张煜哲 523031910110 zhangyuzhe@sjtu.edu.cn

## 项目结构
port_scanner_cpp/
│
├── main.cpp                 # 程序入口，初始化和命令行参数解析
├── CMakeLists.txt           # CMake构建脚本（支持跨平台编译）
│
├── include/                 # 头文件目录
│   ├── scanner/             # 扫描器核心头文件
│   │   ├── base_scanner.h   # 扫描基类
│   │   ├── icmp_scanner.h   # ICMP扫描类
│   │   ├── tcp_scanner.h    # TCP扫描类
│   │   ├── udp_scanner.h    # UDP扫描类
│   │   └── scan_result.h    # 扫描结果结构体
│   │
│   ├── network/             # 网络工具头文件
│   │   ├── socket_utils.h   # 套接字工具函数
│   │   ├── packet_builder.h # 数据包构造
│   │   ├── packet_parser.h  # 数据包解析
│   │   └── ip_port_utils.h  # IP/端口处理
│   │
│   └── utils/               # 通用工具头文件
│       ├── thread_pool.h    # 线程池实现
│       ├── logger.h         # 日志类
│       └── config.h         # 配置管理
│
└── src/                     # 源文件目录
    ├── scanner/             # 扫描器实现
    │   ├── icmp_scanner.cpp
    │   ├── tcp_scanner.cpp
    │   └── udp_scanner.cpp
    │
    ├── network/             # 网络工具实现
    │   ├── socket_utils.cpp
    │   ├── packet_builder.cpp
    │   └── packet_parser.cpp
    │
    └── utils/               # 通用工具实现
        ├── thread_pool.cpp
        ├── logger.cpp
        └── config.cpp 

## 使用方法


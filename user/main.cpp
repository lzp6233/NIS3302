#include <iostream>
#include <vector>
#include <chrono>
#include <string>
#include <fmt/core.h>
#include "ICMP/ping.h"
using namespace std::chrono_literals;
// using namespace icmp_ns;

// ICMP扫描接口
bool icmp_scan(const std::string& ip) {
    const auto timeout = 2500ms;
    for (int i = 0; i < 4; ++i)
    {
        auto duration = icmp_ns::ping(ip, timeout); // 如果 ping 在 icmp_ns 里
        if (duration)
        {
            fmt::print("ping from {}: time={:.2f}ms.\n", ip, duration->count());
        }
        else
        {
            fmt::print("ping from {} timed out, no response after {}ms.\n", ip, timeout.count());
        }
    }
    return true;
}

// TCP端口扫描接口
bool tcp_scan(const std::string& ip, int port) {
    // TODO: 调用TCP扫描实现
    std::cout << "[TCP] 扫描 " << ip << ":" << port << " ...\n";
    // 示例返回值
    return false;
}

int main() {
    std::cout << "请选择扫描类型（1-ICMP，2-TCP）：";
    int scan_type;
    std::cin >> scan_type;

    if (scan_type == 1) {
        std::string target_ip;
        std::cout << "请输入目标IP地址: ";
        std::cin >> target_ip;
        bool alive = icmp_scan(target_ip);
        std::cout << "主机 " << target_ip << (alive ? " 存活" : " 不可达") << std::endl;
    } else if (scan_type == 2) {
        std::string target_ip;
        std::cout << "请输入目标IP地址: ";
        std::cin >> target_ip;

        int port_count;
        std::cout << "请输入要扫描的端口数量: ";
        std::cin >> port_count;

        std::vector<int> ports;
        for (int i = 0; i < port_count; ++i) {
            int port;
            std::cout << "请输入第 " << (i + 1) << " 个端口号: ";
            std::cin >> port;
            ports.push_back(port);
        }

        for (int port : ports) {
            bool open = tcp_scan(target_ip, port);
            std::cout << "端口 " << port << (open ? " 开放" : " 关闭/过滤") << std::endl;
        }
    } else {
        std::cout << "无效的选择，程序退出。" << std::endl;
    }
    return 0;
}
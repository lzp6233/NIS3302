#include <iostream>
#include <vector>
#include <chrono>
#include <string>
#include <fmt/core.h>
#include "ICMP/ping.h"
#include "port/PortScanner.h"
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
            return false; // 如果 ping 超时，返回不可达
        }
    }
    return true;
}

// TCP端口扫描接口
bool tcp_scan(const std::string& ip, int option) {
    // TODO: 调用TCP扫描实现 （tcp connect）
    std::cout << "[TCP] 扫描 " << ip << " ...\n";
    if (option==0) {
        ScanAllPorts(ip);
      }
      else if (option==1) {
        ScanSpecificPort(ip);
      }
      else if (option==2) {
        ScanCommonPorts(ip);
      }
      else {
        std::cout << "Invalid option. Please try again." << std::endl;
      }

    // 示例返回值
    return false;
}

int main() {
    std::cout << "请选择扫描类型（1-ICMP，2-TCP Connect, 3-TCP SYN, 4-TCP FIN, 5-UDP）：";
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

        std::cout << "请选择端口扫描选项（0-扫描所有端口，1-扫描指定端口，2-扫描常见端口）: ";
        int option;
        std::cin >> option;
        while (option < 0 || option > 2) {
            std::cout << "无效的选项，请重新选择。" << std::endl;
        }
        bool open = tcp_scan(target_ip, option);
    } else {
        std::cout << "无效的选择，程序退出。" << std::endl;
    }
    return 0;
}
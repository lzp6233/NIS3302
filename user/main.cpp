/**
 * 网络扫描工具主程序
 * 支持ICMP扫描、TCP端口扫描和UDP端口扫描
 * 包括Connect方式、SYN方式和FIN方式的TCP扫描
 */
#include <iostream>
#include <vector>
#include <chrono>
#include <string>
#include <fmt/core.h>
#include <iomanip>
#include "ICMP/ping.h"
#include "port/PortScanner.h"
using namespace std::chrono_literals;
// using namespace icmp_ns;

// 定义统一输出格式的辅助函数
namespace output {
    // 输出标题
    void title(const std::string& text) {
        std::cout << "\n[+] " << text << "\n";
        std::cout << std::string(60, '-') << std::endl;
    }

    // 输出信息
    void info(const std::string& text) {
        std::cout << "[*] " << text << std::endl;
    }

    // 输出成功信息
    void success(const std::string& text) {
        std::cout << "[✓] " << text << std::endl;
    }

    // 输出错误信息
    void error(const std::string& text) {
        std::cout << "[✗] " << text << std::endl;
    }

    // 输出警告信息
    void warning(const std::string& text) {
        std::cout << "[!] " << text << std::endl;
    }

    // 输出调试信息
    void debug(const std::string& text) {
        std::cout << "[D] " << text << std::endl;
    }

    // 输出详情信息（带缩进）
    void detail(const std::string& text) {
        std::cout << "    " << text << std::endl;
    }
    
    // 输出进度信息
    void progress(int current, int total, const std::string& text = "") {
        int percent = (current * 100) / total;
        std::cout << "\r[*] 进度: [" << std::string(percent/5, '#') << std::string(20-percent/5, ' ') 
                  << "] " << percent << "% " << text << std::flush;
        if (current == total) std::cout << std::endl;
    }
}

/**
 * ICMP扫描函数
 * @param ip 目标IP地址
 * @return 如果目标主机可达则返回true，否则返回false
 */
bool icmp_scan(const std::string& ip) {
    const auto timeout = 2500ms;  // 超时时间设置为2500毫秒
    output::title("ICMP 扫描");
    output::info("正在 ping " + ip + " ...");
    
    for (int i = 0; i < 4; ++i)  // 发送4个ICMP请求
    {
        auto duration = icmp_ns::ping(ip, timeout);
        if (duration)
        {
            output::detail(fmt::format("来自 {} 的回复: 时间={:.2f}ms", ip, duration->count()));
        }
        else
        {
            output::error(fmt::format("来自 {} 的请求超时，{} ms 内无回应", ip, timeout.count()));
            return false;
        }
    }
    return true;
}

/**
 * TCP端口扫描函数
 * @param ip 目标IP地址
 * @param option 扫描选项：0-所有端口，1-指定端口，2-常见端口
 * @return 扫描状态
 */
bool tcp_scan(const std::string& ip, int option) {
    output::title("TCP Connect 扫描");
    output::info("目标: " + ip);
    if (option==0) {
        ScanAllPorts(ip);
    }
    else if (option==1) {
        int port;
        std::cout << "请输入要扫描的端口号: ";
        std::cin >> port;
        ScanSpecificPort(ip, port);
    }
    else if (option==2) {
        ScanCommonPorts(ip);
    }
    else {
        output::error("无效的选项，请重试");
    }

    // 示例返回值
    return false;
}

// 声明接口，不再定义，避免与 PortScanner.cpp 冲突
extern void TCPSynScan(const std::string& ip, int option);
extern void TCPFinScan(const std::string& ip, int option);

/**
 * UDP端口扫描函数
 * @param ip 目标IP地址
 * @param option 扫描选项：0-所有端口，1-指定端口，2-常见端口
 * @return 扫描状态
 */
bool udp_scan(const std::string& ip, int option) {
    output::title("UDP 扫描");
    output::info("目标: " + ip);
    UDPScan(ip, option);
    return false;   
}

/**
 * 主函数
 * 提供用户交互界面，并调用相应的扫描功能
 */
int main() {
    output::title("网络扫描工具");
    std::cout << "请选择扫描类型:\n";
    std::cout << "[1] ICMP 扫描\n";
    std::cout << "[2] TCP Connect 扫描\n";
    std::cout << "[3] TCP SYN 扫描\n";
    std::cout << "[4] TCP FIN 扫描\n";
    std::cout << "[5] UDP 扫描\n";
    std::cout << "请输入选项 (1-5): ";
    
    int scan_type;
    std::cin >> scan_type;

    if (scan_type == 1) {
        // ICMP扫描
        std::string target_ip;
        std::cout << "请输入目标IP地址: ";
        std::cin >> target_ip;
        bool alive = icmp_scan(target_ip);
        if (alive) {
            output::success("主机 " + target_ip + " 存活");
        } else {
            output::error("主机 " + target_ip + " 不可达");
        }
    } else if (scan_type == 2) {
        // TCP Connect扫描
        std::string target_ip;
        std::cout << "请输入目标IP地址: ";
        std::cin >> target_ip;

        std::cout << "请选择端口扫描选项：\n";
        std::cout << "[0] 扫描所有端口\n";
        std::cout << "[1] 扫描指定端口\n";
        std::cout << "[2] 扫描常见端口\n";
        std::cout << "请输入选项 (0-2): ";
        
        int option;
        std::cin >> option;
        while (option < 0 || option > 2) {
            output::error("无效的选项，请重新选择");
            std::cin >> option;
        }
        if (option == 1) {
            int port;
            std::cout << "请输入要扫描的端口号: ";
            std::cin >> port;
            ScanSpecificPort(target_ip, port);
        } else if (option == 0) {
            ScanAllPorts(target_ip);
        } else if (option == 2) {
            ScanCommonPorts(target_ip);
        }
    } 
    else if (scan_type == 3) {
        // TCP SYN扫描
        std::string target_ip;
        std::cout << "请输入目标IP地址: ";
        std::cin >> target_ip;

        std::cout << "请选择端口扫描选项：\n";
        std::cout << "[0] 扫描所有端口\n";
        std::cout << "[1] 扫描指定端口\n";
        std::cout << "[2] 扫描常见端口\n";
        std::cout << "请输入选项 (0-2): ";
        
        int option;
        std::cin >> option;
        while (option < 0 || option > 2) {
            output::error("无效的选项，请重新选择");
            std::cin >> option;
        }
        TCPSynScan(target_ip, option);
    } 
    else if (scan_type == 4) {
        // TCP FIN扫描
        std::string target_ip;
        std::cout << "请输入目标IP地址: ";
        std::cin >> target_ip;

        std::cout << "请选择端口扫描选项：\n";
        std::cout << "[0] 扫描所有端口\n";
        std::cout << "[1] 扫描指定端口\n";
        std::cout << "[2] 扫描常见端口\n";
        std::cout << "请输入选项 (0-2): ";
        
        int option;
        std::cin >> option;
        while (option < 0 || option > 2) {
            output::error("无效的选项，请重新选择");
            std::cin >> option;
        }
        TCPFinScan(target_ip, option);
    } 
    else if (scan_type == 5) {
        // UDP扫描
        std::string target_ip;
        std::cout << "请输入目标IP地址: ";
        std::cin >> target_ip;

        std::cout << "请选择端口扫描选项：\n";
        std::cout << "[0] 扫描所有端口\n";
        std::cout << "[1] 扫描指定端口\n";
        std::cout << "[2] 扫描常见端口\n";
        std::cout << "请输入选项 (0-2): ";
        
        int option;
        std::cin >> option;
        while (option < 0 || option > 2) {
            output::error("无效的选项，请重新选择");
            std::cin >> option;
        }
        bool open = udp_scan(target_ip, option);
    }
    else {
        output::error("无效的选择，程序退出");
    }
    return 0;
}
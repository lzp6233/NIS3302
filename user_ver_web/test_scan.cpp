#include <iostream>
#include <vector>
#include <string>
#include "port/PortScanner.h"


int main() {
    std::string target = "101.43.5.57"; // 使用nmap提供的测试服务器
    std::vector<int> ports = {22, 80, 443, 8080}; // 测试常用端口
    
    std::cout << "开始测试TCP SYN扫描..." << std::endl;
    std::cout << "目标: " << target << std::endl;
    std::cout << "端口: ";
    for (int port : ports) {
        std::cout << port << " ";
    }
    std::cout << std::endl;
    
    // 测试TCP SYN扫描
    std::vector<int> synResults = TCPSynScanJson(target, ports);
    
    std::cout << "\nTCP SYN扫描结果:" << std::endl;
    if (synResults.empty()) {
        std::cout << "未发现开放端口" << std::endl;
    } else {
        std::cout << "发现 " << synResults.size() << " 个开放端口:" << std::endl;
        for (int port : synResults) {
            std::cout << "  端口 " << port << " 开放" << std::endl;
        }
    }
    
    // 测试TCP Connect扫描作为对比
    std::cout << "\n开始测试TCP Connect扫描..." << std::endl;
    std::vector<int> connectResults = tcpConnectScanJson(target, ports);
    
    std::cout << "\nTCP Connect扫描结果:" << std::endl;
    if (connectResults.empty()) {
        std::cout << "未发现开放端口" << std::endl;
    } else {
        std::cout << "发现 " << connectResults.size() << " 个开放端口:" << std::endl;
        for (int port : connectResults) {
            std::cout << "  端口 " << port << " 开放" << std::endl;
        }
    }
    
    return 0;
} 
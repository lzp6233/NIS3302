#include <httplib.h>            // HTTP服务器库
#include <nlohmann/json.hpp>    // JSON处理库
#include <fmt/core.h>           // 格式化库
#include <thread>               // 多线程支持
#include <mutex>                // 互斥锁
#include <vector>               // 向量容器
#include <algorithm>            // 算法库（用于排序）

// 网络相关头文件（用于UDP扫描）
#include <sys/socket.h>         // Socket API
#include <netinet/in.h>         // Internet地址族
#include <arpa/inet.h>          // IP地址转换
#include <unistd.h>             // close函数
#include <cstring>              // memset函数

// 原有功能头文件
#include "ICMP/ping.h"          // ICMP功能
#include "port/PortScanner.h"   // 端口扫描功能

using json = nlohmann::json;

// 处理ICMP扫描请求
json handleIcmpScan(const std::string& target) {
    json result;
    try {
        auto ping_result = icmp_ns::ping(target, std::chrono::milliseconds(1000));  // 调用原有ICMP功能
        bool alive = ping_result.has_value();
        result["status"] = "success";
        result["alive"] = alive;
        result["target"] = target;
        if (alive) {
            result["message"] = "主机可达";
            result["rtt_ms"] = ping_result.value().count();
        } else {
            result["message"] = "主机不可达";
        }
    } catch (const std::exception& e) {
        result["status"] = "error";
        result["message"] = e.what();
    }
    result["timestamp"] = std::time(nullptr);
    return result;
}

// 新增：TCP Connect扫描函数，返回JSON结果
json tcpConnectScan(const std::string& target, const std::vector<int>& ports, int threads = 100) {
    json result;
    std::vector<int> openPorts;
    std::vector<int> filteredPorts;
    
    // 使用多线程进行扫描
    std::vector<std::thread> threadPool;
    std::mutex resultMutex;
    
    // 计算每个线程处理的端口数量
    int portsPerThread = ports.size() / threads;
    if (portsPerThread < 1) portsPerThread = 1;
    
    for (int i = 0; i < threads; ++i) {
        int threadStart = i * portsPerThread;
        int threadEnd = (i == threads - 1) ? ports.size() : (i + 1) * portsPerThread;
        
        if (threadStart < ports.size()) {
            threadPool.emplace_back([&, threadStart, threadEnd]() {
                for (int j = threadStart; j < threadEnd; ++j) {
                    int port = ports[j];
                    if (TestPortConnection(target, port)) {
                        std::lock_guard<std::mutex> lock(resultMutex);
                        openPorts.push_back(port);
                    }
                }
            });
        }
    }
    
    // 等待所有线程完成
    for (auto& thread : threadPool) {
        thread.join();
    }
    
    // 对结果进行排序
    std::sort(openPorts.begin(), openPorts.end());
    
    result["openPorts"] = openPorts;
    result["filteredPorts"] = filteredPorts;
    result["totalScanned"] = ports.size();
    result["openCount"] = openPorts.size();
    result["filteredCount"] = filteredPorts.size();
    
    return result;
}

// 新增：TCP SYN扫描函数，返回JSON结果
json tcpSynScan(const std::string& target, const std::vector<int>& ports) {
    json result;
    // 新实现：调用 PortScanner.cpp 的 TCPSynScanJson
    auto scanResult = TCPSynScanJson(target, ports);
    const std::vector<int>& openPorts = scanResult.first;
    const std::vector<int>& filteredPorts = scanResult.second;
    result["openPorts"] = openPorts;
    result["filteredPorts"] = filteredPorts;
    result["totalScanned"] = ports.size();
    result["openCount"] = openPorts.size();
    result["filteredCount"] = filteredPorts.size();
    result["scanMethod"] = "SYN";
    return result;
}

// 新增：TCP FIN扫描函数，返回JSON结果
json tcpFinScan(const std::string& target, const std::vector<int>& ports) {
    json result;
    // 新实现：调用 PortScanner.cpp 的 TCPFinScanJson
    std::vector<int> openPorts = TCPFinScanJson(target, ports);
    std::vector<int> filteredPorts; // 暂不区分filtered/closed
    result["openPorts"] = openPorts;
    result["filteredPorts"] = filteredPorts;
    result["totalScanned"] = ports.size();
    result["openCount"] = openPorts.size();
    result["filteredCount"] = filteredPorts.size();
    result["scanMethod"] = "FIN";
    return result;
}

// 新增：UDP扫描函数，返回JSON结果
json udpScan(const std::string& target, const std::vector<int>& ports) {
    json result;
    std::vector<int> openPorts;
    std::vector<int> filteredPorts;
    
    // UDP扫描实现
    for (int port : ports) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            continue;
        }
        
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, target.c_str(), &addr.sin_addr);

        struct timeval tv;
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        char sendbuf[1] = {0};
        sendto(sock, sendbuf, sizeof(sendbuf), 0, (struct sockaddr*)&addr, sizeof(addr));

        char recvbuf[1024];
        socklen_t addrlen = sizeof(addr);
        int ret = recvfrom(sock, recvbuf, sizeof(recvbuf), 0, (struct sockaddr*)&addr, &addrlen);
        
        if (ret < 0) {
            // 没有响应，可能是开放或被过滤
            filteredPorts.push_back(port);
        } else {
            // 收到响应，端口开放
            openPorts.push_back(port);
        }
        
        close(sock);
    }
    
    std::sort(openPorts.begin(), openPorts.end());
    std::sort(filteredPorts.begin(), filteredPorts.end());
    
    result["openPorts"] = openPorts;
    result["filteredPorts"] = filteredPorts;
    result["totalScanned"] = ports.size();
    result["openCount"] = openPorts.size();
    result["filteredCount"] = filteredPorts.size();
    result["scanMethod"] = "UDP";
    
    return result;
}

// 处理端口扫描请求
json handlePortScan(const std::string& target, 
                    const std::string& scanType,
                    const std::string& portRange, // "all", "common", "custom"
                    const std::vector<int>& customPorts, // 当portRange为"custom"时使用
                    int threads = 100, int timeout = 1000,
                    bool resolveHostnames = false, bool detectService = false) {
    json result;
    try {
        json scanResult;
        std::vector<int> portsToScan;
        
        // 根据端口范围确定要扫描的端口
        if (portRange == "all") {
            // 扫描全部端口 1-65535
            for (int i = 1; i <= 65535; ++i) {
                portsToScan.push_back(i);
            }
        } else if (portRange == "common") {
            // 使用PortScanner.cpp中定义的常用端口
            // 这里使用PortScanner.cpp中的commonPorts数组
            std::vector<int> commonPorts = {7, 19, 20, 21, 22, 23, 25, 26, 42, 43, 49, 53, 67, 68, 69, 70, 79, 80, 88, 102, 110, 113, 119, 123, 135, 137, 138, 139, 143, 161, 162, 177, 179, 194, 201, 264, 318, 381, 382, 383, 389, 411, 412, 443, 445, 464, 465, 497, 500, 512, 513, 514, 515, 520, 521, 540, 554, 546, 547, 560, 563, 587, 591, 593, 631, 636, 639, 646, 691, 860, 873, 902, 989, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1080, 1194, 1214, 1241, 1311, 1337, 1433, 1434, 1512, 1589, 1701, 1723, 1725, 1741, 1755, 1812, 1813, 1863, 1985, 2000, 2002, 2049, 2077, 2078, 2082, 2083, 2086, 2087, 2095, 2096, 2100, 2222, 2302, 2483, 2484, 2745, 2967, 3050, 3074, 3124, 3127, 3128, 3222, 3260, 3306, 3389, 3689, 3690, 3724, 3784, 3785, 4333, 4444, 4664, 4672, 4899, 5000, 5001, 5004, 5005, 5050, 5060, 5190, 5222, 5223, 5432, 5500, 5554, 5631, 5632, 5800, 5900, 5901, 5902, 5903, 5904, 5905, 5906, 5907, 5908, 5909, 5910, 5911, 5912, 5913, 5914, 5915, 5916, 5917, 5918, 5919, 5920, 5921, 5922, 5923, 5924, 5925, 5926, 5927, 5928, 5929, 5930, 5931, 5932, 5933, 5934, 5935, 5936, 5937, 5938, 5939, 5940, 5941, 5942, 5943, 5944, 5945, 5946, 5947, 5948, 5949, 5950, 5951, 5952, 5953, 5954, 5955, 5956, 5957, 5958, 5959, 5960, 5961, 5962, 5963, 5964, 5965, 5966, 5967, 5968, 5969, 5970, 5971, 5972, 5973, 5974, 5975, 5976, 5977, 5978, 5979, 5980, 5981, 5982, 5983, 5984, 5985, 5986, 5987, 5988, 5989, 5990, 5991, 5992, 5993, 5994, 5995, 5996, 5997, 5998, 5999, 6000, 6001, 6112, 6129, 6257, 6346, 6347, 6500, 6566, 6588, 6665, 6666, 6667, 6668, 6669, 6679, 6697, 6699, 6881, 6891, 6892, 6893, 6894, 6895, 6896, 6897, 6898, 6899, 6900, 6901, 6970, 7212, 7648, 7649, 8000, 8080, 8086, 8087, 8118, 8200, 8500, 8767, 8866, 9100, 9101, 9102, 9103, 9119, 9800, 9898, 9988, 9999, 10000, 10113, 10114, 10115, 10116, 11371, 12035, 12036, 12345, 13720, 13721, 14567, 15118, 19226, 19638, 20000, 24800, 25999, 27015, 27017, 27374, 28960, 31337};
            portsToScan = commonPorts;
        } else if (portRange == "custom") {
            // 使用指定的端口数组
            portsToScan = customPorts;
        } else {
            throw std::invalid_argument("不支持的端口范围: " + portRange);
        }
        
        // 根据扫描类型执行不同的扫描方法
        if (scanType == "connect") {
            scanResult = tcpConnectScan(target, portsToScan, threads);
        } else if (scanType == "syn") {
            scanResult = tcpSynScan(target, portsToScan);
        } else if (scanType == "fin") {
            scanResult = tcpFinScan(target, portsToScan);
        } else if (scanType == "udp") {
            scanResult = udpScan(target, portsToScan);
        } else {
            throw std::invalid_argument("不支持的扫描类型: " + scanType);
        }
        

        // 构建最终结果
        result["status"] = "success";
        result["target"] = target;
        result["scanType"] = scanType;
        result["portRange"] = portRange;
        result["openPorts"] = scanResult["openPorts"];
        result["filteredPorts"] = scanResult["filteredPorts"];
        result["totalPorts"] = portsToScan.size();
        result["openPortCount"] = scanResult["openCount"];
        result["filteredPortCount"] = scanResult["filteredCount"];
        result["scanMethod"] = scanResult.value("scanMethod", scanType);
        
    } catch (const std::exception& e) {
        result["status"] = "error";
        result["message"] = e.what();
    }
    result["timestamp"] = std::time(nullptr);
    return result;
}

int main() {
    // 创建HTTP服务器
    httplib::Server svr;
    
    // 设置CORS头，允许前端跨域访问（只用 set_default_headers，Options handler 不再重复设置）
    svr.set_default_headers({
        {"Access-Control-Allow-Origin", "*"},
        {"Access-Control-Allow-Methods", "GET, POST, OPTIONS"},
        {"Access-Control-Allow-Headers", "Content-Type"}
    });
    
    // 设置静态文件服务
    svr.set_mount_point("/", "./");
    
    // 处理OPTIONS预检请求（不再重复设置CORS头，只返回200即可）
    svr.Options("/(.*)", [](const httplib::Request&, httplib::Response& res) {
        res.status = 200;
    });
    
    // 统一的扫描端点 - 处理前端POST请求
    svr.Post("/scan", [](const httplib::Request& req, httplib::Response& res) {
        // 输出收到的原始请求体，便于调试
        std::cout << "[DEBUG] /scan 收到请求体: " << req.body << std::endl;
        std::cout << "[DEBUG] Content-Type: " << req.get_header_value("Content-Type") << std::endl;
        try {
            // 解析JSON请求体
            json requestData = json::parse(req.body);
            
            // 提取参数
            std::string target = requestData["target"];
            std::string scanType = requestData["scanType"];
            
            json result;
            
            // 根据扫描类型处理
            std::cout << "[DEBUG] 扫描类型: " << scanType << std::endl;
            if (scanType == "icmp") {
                std::cout << "[DEBUG] 执行ICMP扫描" << std::endl;
                result = handleIcmpScan(target);
            } else {
                std::cout << "[DEBUG] 执行端口扫描" << std::endl;
                // 端口扫描
                std::string portRange = requestData.value("portRange", "all"); // 新增portRange参数
                std::vector<int> customPorts;
                if (portRange == "custom") {
                    auto portsJson = requestData["customPorts"];
                    if (portsJson.is_array()) {
                        for (const auto& port : portsJson) {
                            if (port.is_number_integer()) {
                                customPorts.push_back(port.get<int>());
                            }
                        }
                    }
                }
                int threads = requestData.value("threads", 100);
                int timeout = requestData.value("timeout", 1000);
                bool resolveHostnames = requestData.value("resolveHostnames", false);
                bool detectService = requestData.value("detectService", false);
                
                result = handlePortScan(target, scanType, portRange, customPorts, 
                                     threads, timeout, resolveHostnames, detectService);
            }
            
            std::cout << "[DEBUG] 返回结果: " << result.dump() << std::endl;
            res.set_content(result.dump(), "application/json");
            
        } catch (const json::exception& e) {
            res.status = 400;
            res.set_content(json({{"status", "error"}, {"message", "JSON解析错误: " + std::string(e.what())}}).dump(), "application/json");
        } catch (const std::exception& e) {
            res.status = 500;
            res.set_content(json({{"status", "error"}, {"message", e.what()}}).dump(), "application/json");
        }
    });
    
    // 服务器根路径 - 返回API文档
    svr.Get("/api", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(R"(
            <h1>端口扫描API文档</h1>
            <h2>统一扫描接口</h2>
            <p>POST /scan</p>
            <p>请求体格式: {"target": "example.com", "scanType": "connect", "portRange": "all", "customPorts": [1, 2, 3]}</p>
            
            <h2>扫描类型</h2>
            <ul>
                <li>icmp - ICMP主机存活检测</li>
                <li>connect - TCP连接扫描</li>
                <li>syn - TCP SYN扫描</li>
                <li>fin - TCP FIN扫描</li>
                <li>udp - UDP扫描</li>
            </ul>
        )", "text/html");
    });
    
    // 保留原有的GET接口作为备用
    svr.Get("/icmp", [](const httplib::Request& req, httplib::Response& res) {
        if (!req.has_param("target")) {
            res.status = 400;
            res.set_content(json({{"status", "error"}, {"message", "缺少'target'参数"}}).dump(), "application/json");
            return;
        }
        
        std::string target = req.get_param_value("target");
        json result = handleIcmpScan(target);
        res.set_content(result.dump(), "application/json");
    });
    
    svr.Get("/portscan", [](const httplib::Request& req, httplib::Response& res) {
        // 检查必需参数
        if (!req.has_param("target") || !req.has_param("scanType") || 
            !req.has_param("start") || !req.has_param("end")) {
            res.status = 400;
            res.set_content(json({{"status", "error"}, {"message", "缺少必需参数"}}).dump(), "application/json");
            return;
        }
        
        // 解析参数
        std::string target = req.get_param_value("target");
        std::string scanType = req.get_param_value("scanType");
        int startPort = std::stoi(req.get_param_value("start"));
        int endPort = std::stoi(req.get_param_value("end"));
        
        // 解析可选参数
        int threads = req.has_param("threads") ? std::stoi(req.get_param_value("threads")) : 100;
        int timeout = req.has_param("timeout") ? std::stoi(req.get_param_value("timeout")) : 1000;
        bool resolveHostnames = req.has_param("resolve") ? (req.get_param_value("resolve") == "true") : false;
        bool detectService = req.has_param("service") ? (req.get_param_value("service") == "true") : false;
        
        // 执行扫描
        json result = handlePortScan(target, scanType, "custom", {startPort, endPort}, 
                                    threads, timeout, resolveHostnames, detectService);
        res.set_content(result.dump(), "application/json");
    });
    
    // 启动服务器
    fmt::print("端口扫描API服务器已启动，访问 http://localhost:8080\n");
    fmt::print("前端页面: http://localhost:8080/port_scanner.html\n");
    fmt::print("API文档: http://localhost:8080/api\n");
    fmt::print("按 Ctrl+C 停止服务器\n");
    svr.listen("localhost", 8080);
    
    return 0;
}
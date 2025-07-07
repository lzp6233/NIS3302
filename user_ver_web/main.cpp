#include <httplib.h>            // HTTP服务器库
#include <nlohmann/json.hpp>    // JSON处理库
#include <fmt/core.h>           // 格式化库

// 原有功能头文件
#include "ICMP/ping.h"          // ICMP功能
#include "port/PortScanner.h"   // 端口扫描功能

using json = nlohmann::json;

// 处理ICMP扫描请求
json handleIcmpScan(const std::string& target) {
    json result;
    try {
        bool alive = ping(target);  // 调用原有ICMP功能
        result["status"] = "success";
        result["alive"] = alive;
        result["target"] = target;
        result["message"] = alive ? "主机可达" : "主机不可达";
    } catch (const std::exception& e) {
        result["status"] = "error";
        result["message"] = e.what();
    }
    result["timestamp"] = std::time(nullptr);
    return result;
}

// 处理端口扫描请求
json handlePortScan(const std::string& target, 
                    const std::string& scanType,
                    int startPort, int endPort,
                    int threads = 100, int timeout = 1000,
                    bool resolveHostnames = false, bool detectService = false) {
    json result;
    try {
        // 创建端口扫描器实例
        PortScanner scanner(target, startPort, endPort);
        
        // 设置扫描选项
        scanner.setThreads(threads);
        scanner.setTimeout(timeout);
        scanner.setResolveHostnames(resolveHostnames);
        scanner.setDetectService(detectService);
        
        // 根据扫描类型执行不同的扫描方法
        std::vector<int> openPorts;
        if (scanType == "connect") {
            openPorts = scanner.tcpConnectScan();
        } else if (scanType == "syn") {
            openPorts = scanner.tcpSynScan();
        } else if (scanType == "fin") {
            openPorts = scanner.tcpFinScan();
        } else if (scanType == "udp") {
            openPorts = scanner.udpScan();
        } else {
            throw std::invalid_argument("不支持的扫描类型: " + scanType);
        }
        
        // 构建结果
        result["status"] = "success";
        result["target"] = target;
        result["scanType"] = scanType;
        result["startPort"] = startPort;
        result["endPort"] = endPort;
        result["openPorts"] = openPorts;
        result["totalPorts"] = endPort - startPort + 1;
        result["openPortCount"] = openPorts.size();
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
    
    // 服务器根路径 - 返回API文档
    svr.Get("/", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(R"(
            <h1>端口扫描API文档</h1>
            <h2>ICMP扫描</h2>
            <p>/icmp?target=example.com</p>
            
            <h2>端口扫描</h2>
            <p>/portscan?target=example.com&scanType=connect&start=1&end=100</p>
            <p>scanType可选值: connect, syn, fin, udp</p>
        )", "text/html");
    });
    
    // 定义ICMP扫描接口
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
    
    // 定义端口扫描接口
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
        json result = handlePortScan(target, scanType, startPort, endPort, 
                                    threads, timeout, resolveHostnames, detectService);
        res.set_content(result.dump(), "application/json");
    });
    
    // 启动服务器
    fmt::print("端口扫描API服务器已启动，访问 http://localhost:8080\n");
    fmt::print("按 Ctrl+C 停止服务器\n");
    svr.listen("localhost", 8080);
    
    return 0;
}
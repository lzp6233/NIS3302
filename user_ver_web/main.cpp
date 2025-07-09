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

// 处理端口扫描请求
json handlePortScan(const std::string& target, 
                    const std::string& scanType,
                    int startPort, int endPort,
                    int threads = 100, int timeout = 1000,
                    bool resolveHostnames = false, bool detectService = false) {
    json result;
    try {
        std::vector<int> openPorts;
        std::vector<int> filteredPorts; // 添加过滤端口列表
        
        // 根据扫描类型执行不同的扫描方法
        if (scanType == "connect") {
            // 直接测试端口连通性
            for (int port = startPort; port <= endPort; ++port) {
                if (TestPortConnection(target, port)) {
                    openPorts.push_back(port);
                }
            }
        } else if (scanType == "syn") {
            // 这里需要根据实际的TCPSynScan函数签名调整
            // TCPSynScan(target, 0); // 暂时注释掉，需要确认函数签名
            // 临时使用connect方式
            for (int port = startPort; port <= endPort; ++port) {
                if (TestPortConnection(target, port)) {
                    openPorts.push_back(port);
                }
            }
        } else if (scanType == "fin") {
            // TCPFinScan(target, 0); // 暂时注释掉，需要确认函数签名
            // 临时使用connect方式
            for (int port = startPort; port <= endPort; ++port) {
                if (TestPortConnection(target, port)) {
                    openPorts.push_back(port);
                }
            }
        } else if (scanType == "udp") {
            // UDPScan(target, 0); // 暂时注释掉，需要确认函数签名
            // 临时使用connect方式
            for (int port = startPort; port <= endPort; ++port) {
                if (TestPortConnection(target, port)) {
                    openPorts.push_back(port);
                }
            }
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
        result["filteredPorts"] = filteredPorts; // 添加过滤端口
        result["totalPorts"] = endPort - startPort + 1;
        result["openPortCount"] = openPorts.size();
        result["filteredPortCount"] = filteredPorts.size();
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
        try {
            // 解析JSON请求体
            json requestData = json::parse(req.body);
            
            // 提取参数
            std::string target = requestData["target"];
            std::string scanType = requestData["scanType"];
            
            json result;
            
            // 根据扫描类型处理
            if (scanType == "icmp") {
                result = handleIcmpScan(target);
            } else {
                // 端口扫描
                int portStart = requestData.value("portStart", 1);
                int portEnd = requestData.value("portEnd", 1024);
                int threads = requestData.value("threads", 100);
                int timeout = requestData.value("timeout", 1000);
                bool resolveHostnames = requestData.value("resolveHostnames", false);
                bool detectService = requestData.value("detectService", false);
                
                result = handlePortScan(target, scanType, portStart, portEnd, 
                                     threads, timeout, resolveHostnames, detectService);
            }
            
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
            <p>请求体格式: {"target": "example.com", "scanType": "connect", "portStart": 1, "portEnd": 100}</p>
            
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
        json result = handlePortScan(target, scanType, startPort, endPort, 
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
#include <iostream>
#include <string>
#include <fmt/format.h>
#include <httplib.h>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// 原有的扫描函数声明
bool icmp_scan(const std::string& ip);
bool tcp_scan(const std::string& ip, int option);
bool tcp_syn_scan(const std::string& ip, int option);
bool tcp_fin_scan(const std::string& ip, int option);
bool udp_scan(const std::string& ip, int option);

// 处理扫描请求的函数
void handleScanRequest(const httplib::Request& req, httplib::Response& res) {
    try {
        // 解析请求体中的JSON数据
        auto jsonData = json::parse(req.body);
        std::string target = jsonData["target"];
        std::string scanType = jsonData["scanType"];
        int portStart = jsonData["portStart"];
        int portEnd = jsonData["portEnd"];
        int option = 0; // 默认扫描所有端口
        if (portStart == 1 && portEnd == 100) {
            option = 2; // 扫描常见端口
        } else if (portStart != 1 || portEnd != 65535) {
            option = 1; // 扫描指定端口
        }

        json result;
        if (scanType == "icmp") {
            // 处理ICMP扫描
            bool alive = icmp_scan(target);
            result["alive"] = alive;
        } else if (scanType == "connect") {
            // 处理TCP Connect扫描
            bool open = tcp_scan(target, option);
            result["open"] = open;
        } else if (scanType == "syn") {
            // 处理TCP SYN扫描
            bool open = tcp_syn_scan(target, option);
            result["open"] = open;
        } else if (scanType == "fin") {
            // 处理TCP FIN扫描
            bool open = tcp_fin_scan(target, option);
            result["open"] = open;
        } else if (scanType == "udp") {
            // 处理UDP扫描
            bool open = udp_scan(target, option);
            result["open"] = open;
        }

        // 设置响应头和响应体
        res.set_header("Content-Type", "application/json");
        res.set_content(result.dump(), "application/json");
    } catch (const std::exception& e) {
        // 处理异常
        res.status = 500;
        res.set_content(fmt::format("Error: {}", e.what()), "text/plain");
    }
}

int main() {
    // 创建HTTP服务器
    httplib::Server svr;

    // 定义扫描接口
    svr.Post("/scan", handleScanRequest);

    // 启动服务器
    std::cout << "Server started on port 8080..." << std::endl;
    svr.listen("localhost", 8080);

    return 0;
}
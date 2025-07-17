/**
 * WebPortScanner - 网页版端口扫描工具
 * 主程序文件 - 提供HTTP API服务和端口扫描功能
 * 
 * 该程序实现了一个基于HTTP的端口扫描API服务器，支持ICMP存活检测、TCP连接扫描、
 * TCP SYN扫描、TCP FIN扫描和UDP扫描等多种扫描方式，并提供JSON格式的扫描结果。
 */

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
#include <netinet/ip.h>         // IP头部定义
#include <netinet/ip_icmp.h>    // ICMP头部定义

// libpcap相关头文件（用于捕获ICMP错误消息）
#include <pcap/pcap.h>
#include <netinet/udp.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/if_ether.h>
#include <ifaddrs.h>

// 原有功能头文件
#include "ICMP/ping.h"          // ICMP功能
#include "port/PortScanner.h"   // 端口扫描功能

using json = nlohmann::json;

/**
 * 处理ICMP扫描请求
 * 向目标主机发送ICMP Echo请求，检测其是否存活
 * 
 * @param target 目标主机IP地址或域名
 * @return json对象，包含扫描结果信息
 */
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

/**
 * TCP Connect扫描函数
 * 使用TCP全连接方式扫描目标主机的指定端口
 * 
 * @param target 目标主机IP地址或域名
 * @param ports 要扫描的端口列表
 * @param threads 并发线程数
 * @return json对象，包含开放端口、关闭端口和过滤端口的信息
 */
json tcpConnectScan(const std::string& target, const std::vector<int>& ports, int threads = 100) {
    json result;
    std::vector<int> openPorts;
    std::vector<int> closedPorts;
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
                    } else {
                        std::lock_guard<std::mutex> lock(resultMutex);
                        closedPorts.push_back(port);
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
    std::sort(closedPorts.begin(), closedPorts.end());
    
    result["openPorts"] = openPorts;
    result["closedPorts"] = closedPorts;
    result["filteredPorts"] = filteredPorts;
    result["totalScanned"] = ports.size();
    result["openCount"] = openPorts.size();
    result["closedCount"] = closedPorts.size();
    result["filteredCount"] = filteredPorts.size();
    
    return result;
}

/**
 * TCP SYN扫描函数
 * 使用TCP SYN半连接方式扫描目标主机的指定端口
 * 
 * @param target 目标主机IP地址
 * @param ports 要扫描的端口列表
 * @return json对象，包含开放端口、关闭端口和过滤端口的信息
 */
json tcpSynScan(const std::string& target, const std::vector<int>& ports) {
    json result;
    // 新实现：调用 PortScanner.cpp 的 TCPSynScanJson
    std::vector<int> openPorts = TCPSynScanJson(target, ports);
    std::vector<int> filteredPorts; // 暂不区分filtered/closed
    
    // 计算关闭端口（所有扫描的端口减去开放和过滤的端口）
    std::vector<int> closedPorts;
    for (int port : ports) {
        bool isOpen = std::find(openPorts.begin(), openPorts.end(), port) != openPorts.end();
        bool isFiltered = std::find(filteredPorts.begin(), filteredPorts.end(), port) != filteredPorts.end();
        if (!isOpen && !isFiltered) {
            closedPorts.push_back(port);
        }
    }
    
    result["openPorts"] = openPorts;
    result["closedPorts"] = closedPorts;
    result["filteredPorts"] = filteredPorts;
    result["totalScanned"] = ports.size();
    result["openCount"] = openPorts.size();
    result["closedCount"] = closedPorts.size();
    result["filteredCount"] = filteredPorts.size();
    result["scanMethod"] = "SYN";
    return result;
}

/**
 * TCP FIN扫描函数
 * 使用TCP FIN包扫描目标主机的指定端口
 * 
 * @param target 目标主机IP地址
 * @param ports 要扫描的端口列表
 * @return json对象，包含开放端口、关闭端口和过滤端口的信息
 */
json tcpFinScan(const std::string& target, const std::vector<int>& ports) {
    json result;
    // 新实现：调用 PortScanner.cpp 的 TCPFinScanJson
    std::vector<int> openPorts = TCPFinScanJson(target, ports);
    std::vector<int> filteredPorts; // 暂不区分filtered/closed
    
    // 计算关闭端口（所有扫描的端口减去开放和过滤的端口）
    std::vector<int> closedPorts;
    for (int port : ports) {
        bool isOpen = std::find(openPorts.begin(), openPorts.end(), port) != openPorts.end();
        bool isFiltered = std::find(filteredPorts.begin(), filteredPorts.end(), port) != filteredPorts.end();
        if (!isOpen && !isFiltered) {
            closedPorts.push_back(port);
        }
    }
    
    result["openPorts"] = openPorts;
    result["closedPorts"] = closedPorts;
    result["filteredPorts"] = filteredPorts;
    result["totalScanned"] = ports.size();
    result["openCount"] = openPorts.size();
    result["closedCount"] = closedPorts.size();
    result["filteredCount"] = filteredPorts.size();
    result["scanMethod"] = "FIN";
    return result;
}

/**
 * 获取目标IP对应的网络接口
 * 根据目标IP选择合适的网络接口进行扫描
 * 
 * @param target_ip 目标IP地址
 * @return 适合与目标IP通信的网络接口名称
 */
std::string get_interface_for_target(const std::string& target_ip) {
    // 如果目标是本地主机，优先使用lo接口
    if (target_ip == "127.0.0.1" || target_ip == "localhost") {
        struct ifaddrs *ifap, *ifa;
        if (getifaddrs(&ifap) == -1) {
            return "lo";
        }
        
        for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
                char addr[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &sa->sin_addr, addr, INET_ADDRSTRLEN);
                
                if (strcmp(addr, "127.0.0.1") == 0) {
                    std::string lo_iface = ifa->ifa_name;
                    freeifaddrs(ifap);
                    return lo_iface;
                }
            }
        }
        freeifaddrs(ifap);
    }
    
    // 对于其他IP，使用非回环接口
    struct ifaddrs *ifap, *ifa;
    std::string iface;
    
    if (getifaddrs(&ifap) == -1) {
        return "eth0"; // 返回默认接口
    }
    
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
            char addr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &sa->sin_addr, addr, INET_ADDRSTRLEN);
            
            // 排除回环接口，只选择非回环接口
            if (strcmp(ifa->ifa_name, "lo") == 0 || strcmp(addr, "127.0.0.1") == 0) {
                continue;
            }
            
            // 检查接口是否处于UP状态
            if (!(ifa->ifa_flags & IFF_UP)) {
                continue;
            }
            
            // 取第一个非回环的接口
            if (iface.empty()) {
                iface = ifa->ifa_name;
                break;
            }
        }
    }
    
    freeifaddrs(ifap);
    
    // 如果没有找到非回环接口，尝试常见的接口名称
    if (iface.empty()) {
        std::vector<std::string> common_interfaces = {"eth0", "ens33", "ens160", "enp0s3", "eno1", "wlan0"};
        for (const auto& common_iface : common_interfaces) {
            // 检查接口是否存在（通过尝试打开pcap）
            char errbuf[PCAP_ERRBUF_SIZE];
            pcap_t *test_handle = pcap_open_live(common_iface.c_str(), 65536, 1, 1000, errbuf);
            if (test_handle != NULL) {
                pcap_close(test_handle);
                iface = common_iface;
                break;
            }
        }
    }
    
    return iface;
}

// 新增：UDP扫描函数，返回JSON结果
json udpScan(const std::string& target, const std::vector<int>& ports) {
    json result;
    std::vector<int> openPorts;
    std::vector<int> filteredPorts;
    std::vector<int> closedPorts;
    
    // 增加超时时间到3秒（避免网络延迟导致漏检）
    const int SCAN_TIMEOUT = 3;
    
    for (int port : ports) {
        std::atomic<bool> port_closed(false);
        std::atomic<bool> thread_running(true);
        std::mutex mtx;
        std::condition_variable cv;
        
        // 调试标记：是否捕获到任何ICMP包
        std::atomic<bool> captured_icmp(false);
        
        std::string iface = get_interface_for_target(target);
        
        // 打开pcap句柄（超时设为100ms，避免阻塞过久）
        char pcap_errbuf[PCAP_ERRBUF_SIZE] = {0};
        pcap_t* handle = pcap_open_live(iface.c_str(), 65536, 1, 100, pcap_errbuf);
        if (!handle) {
            // 如果pcap初始化失败，使用简化的UDP扫描
            int sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (sock < 0) {
                closedPorts.push_back(port);
                continue;
            }
            
            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_port = htons(port);
            inet_pton(AF_INET, target.c_str(), &addr.sin_addr);

            struct timeval tv;
            tv.tv_sec = SCAN_TIMEOUT;
            tv.tv_usec = 0;
            setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

            const char* payload = "NIS3302_UDP_SCAN";
            int send_len = sendto(sock, payload, strlen(payload), 0, (struct sockaddr*)&addr, sizeof(addr));
            
            if (send_len < 0) {
                filteredPorts.push_back(port);
                close(sock);
                continue;
            }

            char recvbuf[1024];
            socklen_t addrlen = sizeof(addr);
            int ret = recvfrom(sock, recvbuf, sizeof(recvbuf), 0, (struct sockaddr*)&addr, &addrlen);
            
            if (ret > 0) {
                openPorts.push_back(port);
            } else {
                filteredPorts.push_back(port);
            }
            
            close(sock);
            continue;
        }

        // 设置非阻塞模式
        if (pcap_setnonblock(handle, 1, pcap_errbuf) == -1) {
            pcap_close(handle);
            filteredPorts.push_back(port);
            continue;
        }

        // 过滤规则：捕获目标IP的ICMP类型3消息（包含端口不可达）
        std::string filter_exp = "icmp[0] == 3 and src host " + target;
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1 ||
            pcap_setfilter(handle, &fp) == -1) {
            pcap_close(handle);
            filteredPorts.push_back(port);
            continue;
        }
        pcap_freecode(&fp);

        // 创建UDP套接字
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            pcap_close(handle);
            closedPorts.push_back(port);
            continue;
        }

        // 配置目标地址
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, target.c_str(), &addr.sin_addr);

        // 设置UDP接收超时（与扫描超时一致）
        struct timeval tv;
        tv.tv_sec = SCAN_TIMEOUT;
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        // 抓包线程：重点调试ICMP捕获逻辑
        std::thread sniffer([&]() {
            auto start_time = std::chrono::steady_clock::now();
            int pkt_count = 0;  // 记录捕获的数据包总数

            while (thread_running && 
                   std::chrono::duration_cast<std::chrono::seconds>(
                       std::chrono::steady_clock::now() - start_time
                   ).count() < SCAN_TIMEOUT) {

                struct pcap_pkthdr* header;
                const u_char* pkt_data;
                int res = pcap_next_ex(handle, &header, &pkt_data);

                if (res != 1) {
                    // 无数据包或错误，短暂休眠后继续
                    std::this_thread::sleep_for(std::chrono::milliseconds(50));
                    continue;
                }

                pkt_count++;

                // 1. 解析链路层，定位IP头部
                int linktype = pcap_datalink(handle);
                const u_char* ip_pkt = nullptr;
                switch (linktype) {
                    case DLT_EN10MB:    ip_pkt = pkt_data + 14; break;  // 以太网
                    case DLT_LINUX_SLL: ip_pkt = pkt_data + 16; break;  // Linux虚拟链路
                    case DLT_NULL:      ip_pkt = pkt_data + 4; break;   // _loopback
                    case DLT_RAW:       ip_pkt = pkt_data; break;       // 原始IP包
                    default:
                        continue;
                }

                // 校验IP头部是否完整
                if (ip_pkt + sizeof(struct iphdr) > pkt_data + header->caplen) {
                    continue;
                }

                // 2. 解析IP头部
                const struct iphdr* ip_hdr = (const struct iphdr*)ip_pkt;
                if (ip_hdr->protocol != IPPROTO_ICMP) {
                    continue;
                }

                // 3. 验证IP源地址
                struct in_addr src_ip;
                src_ip.s_addr = ip_hdr->saddr;
                std::string src_ip_str = inet_ntoa(src_ip);
                if (src_ip_str != target) continue;

                // 4. 解析ICMP头部
                int ip_hdr_len = ip_hdr->ihl * 4;
                const u_char* icmp_pkt = ip_pkt + ip_hdr_len;
                if (icmp_pkt + 2 > pkt_data + header->caplen) {  // 至少需要2字节（类型+代码）
                    continue;
                }

                uint8_t icmp_type = icmp_pkt[0];
                uint8_t icmp_code = icmp_pkt[1];
                captured_icmp = true;  // 标记捕获到ICMP包

                // 5. 校验ICMP类型和代码（必须是类型3，代码3才是端口不可达）
                if (icmp_type != 3 || icmp_code != 3) {
                    continue;
                }

                // 6. 解析ICMP中包含的原始UDP包（错误数据区）
                const u_char* orig_ip_pkt = icmp_pkt + 8;  // 跳过ICMP错误头部（8字节）
                if (orig_ip_pkt + sizeof(struct iphdr) > pkt_data + header->caplen) {
                    continue;
                }

                const struct iphdr* orig_ip_hdr = (const struct iphdr*)orig_ip_pkt;
                if (orig_ip_hdr->protocol != IPPROTO_UDP) {
                    continue;
                }

                // 7. 解析原始UDP头部，提取目标端口
                int orig_ip_len = orig_ip_hdr->ihl * 4;
                const u_char* orig_udp_pkt = orig_ip_pkt + orig_ip_len;
                if (orig_udp_pkt + sizeof(struct udphdr) > pkt_data + header->caplen) {
                    continue;
                }

                const struct udphdr* orig_udp_hdr = (const struct udphdr*)orig_udp_pkt;
                uint16_t orig_dst_port = ntohs(orig_udp_hdr->dest);

                // 8. 验证端口是否匹配当前扫描端口
                if (orig_dst_port == port) {
                    port_closed = true;
                    break;  // 找到匹配的包，退出抓包
                }
            }

            thread_running = false;
            cv.notify_one();
        });

        // 发送UDP探测包（使用非空载荷，提高被响应概率）
        const char* payload = "NIS3302_UDP_SCAN";
        int send_len = sendto(sock, payload, strlen(payload), 0, (struct sockaddr*)&addr, sizeof(addr));
        
        if (send_len < 0) {
            filteredPorts.push_back(port);
            close(sock);
            pcap_close(handle);
            continue;
        }

        // 等待UDP响应
        char recvbuf[1024];
        socklen_t addrlen = sizeof(addr);
        int ret = recvfrom(sock, recvbuf, sizeof(recvbuf), 0, (struct sockaddr*)&addr, &addrlen);

        // 等待抓包线程结束
        {
            std::unique_lock<std::mutex> lock(mtx);
            cv.wait_for(lock, std::chrono::seconds(SCAN_TIMEOUT), [&]{ return !thread_running; });
        }
        thread_running = false;
        sniffer.join();

        // 最终判定
        if (port_closed) {
            closedPorts.push_back(port);
        } else if (ret > 0) {
            openPorts.push_back(port);
        } else {
            filteredPorts.push_back(port);
        }

        // 清理资源
        pcap_close(handle);
        close(sock);
    }
    
    std::sort(openPorts.begin(), openPorts.end());
    std::sort(filteredPorts.begin(), filteredPorts.end());
    std::sort(closedPorts.begin(), closedPorts.end());
    
    result["openPorts"] = openPorts;
    result["closedPorts"] = closedPorts;
    result["filteredPorts"] = filteredPorts;
    result["totalScanned"] = ports.size();
    result["openCount"] = openPorts.size();
    result["closedCount"] = closedPorts.size();
    result["filteredCount"] = filteredPorts.size();
    result["scanMethod"] = "UDP";
    
    return result;
}

/**
 * 处理端口扫描请求
 * 统一处理各种类型的端口扫描请求
 * 
 * @param target 目标主机IP地址或域名
 * @param scanType 扫描类型：connect, syn, fin, udp
 * @param portRange 端口范围：all, common, custom
 * @param customPorts 自定义端口列表
 * @param threads 并发线程数
 * @param timeout 超时时间(毫秒)
 * @param resolveHostnames 是否解析主机名
 * @param detectService 是否检测服务
 * @return json对象，包含扫描结果信息
 */
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
            // 使用精简的常用端口列表，与前端保持一致
            std::vector<int> commonPorts = {
                20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 119, 123, 135, 137, 138, 139, 143, 161, 162,
                389, 443, 445, 465, 514, 515, 520, 587, 631, 636, 993, 995, 1080, 1433, 1434, 1521, 1723,
                3306, 3389, 5432, 5900, 5901, 5984, 6379, 8080, 8081, 8443, 9000, 9090, 9200, 27017, 27018, 27019
            };
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
        result["closedPorts"] = scanResult.value("closedPorts", json::array());
        result["filteredPorts"] = scanResult["filteredPorts"];
        result["totalPorts"] = portsToScan.size();
        result["openPortCount"] = scanResult["openCount"];
        result["closedPortCount"] = scanResult.value("closedCount", 0);
        result["filteredPortCount"] = scanResult["filteredCount"];
        result["scanMethod"] = scanResult.value("scanMethod", scanType);
        
    } catch (const std::exception& e) {
        result["status"] = "error";
        result["message"] = e.what();
    }
    result["timestamp"] = std::time(nullptr);
    return result;
}

/**
 * 主函数
 * 创建并启动HTTP服务器，处理前端请求
 */
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
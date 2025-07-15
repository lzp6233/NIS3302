/*
- How to turn URLs into IP addresses?
*/

#include <sys/time.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <string>
#include <iostream>
#include <vector>
#include <thread>
#include <mutex>
#include <chrono>
#include <algorithm>
#include <bits/stdc++.h>
#include <libnet.h>
#include <pcap.h>
#include <ifaddrs.h>
#include <errno.h>
#include <string.h>
#include <random>

// 前向声明
std::vector<int> tcpConnectScanJson(const std::string& ip, const std::vector<int>& ports);

// 声明外部函数，解决未声明报错
std::string get_interface_for_target(const std::string& target_ip);

// 全局随机数生成器，提高随机性
std::random_device rd;
std::mt19937 gen(rd());
std::uniform_int_distribution<> dis(1, 65535);

std::mutex bufferLock;


// 精简的常用端口列表，与前端保持一致
std::vector<int> commonPorts = {
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 119, 123, 135, 137, 138, 139, 143, 161, 162,
    389, 443, 445, 465, 514, 515, 520, 587, 631, 636, 993, 995, 1080, 1433, 1434, 1521, 1723,
    3306, 3389, 5432, 5900, 5901, 5984, 6379, 8080, 8081, 8443, 9000, 9090, 9200, 27017, 27018, 27019
};



bool TestPortConnection(std::string ip, int port) {
    // 对重要端口（如3306）进行多次重试
    int max_retries = (port == 3306) ? 3 : 1;
    
    for (int retry = 0; retry < max_retries; retry++) {
        //creates a socket on your machine and connects to the port of the IP address specified
        struct sockaddr_in address;
        int myNetworkSocket = -1;

        address.sin_family = AF_INET;
        address.sin_addr.s_addr = inet_addr(ip.c_str());
        address.sin_port = htons(port);

        myNetworkSocket = socket(AF_INET, SOCK_STREAM, 0);

        if (myNetworkSocket == -1) {
            if (port == 3306) {
                std::cout << "Socket creation failed on port " << port << " (retry " << retry + 1 << ")" << std::endl;
            }
            continue;
        }

        // 设置socket选项
        int opt = 1;
        setsockopt(myNetworkSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

        fcntl(myNetworkSocket, F_SETFL, O_NONBLOCK);

        int ret = connect(myNetworkSocket, (struct sockaddr *)&address, sizeof(address));
        if (ret == 0) {
            close(myNetworkSocket);
            if (port == 3306 && retry > 0) {
                std::cout << "MySQL端口3306在第" << retry + 1 << "次重试时连接成功" << std::endl;
            }
            return true;
        } else if (errno != EINPROGRESS) {
            close(myNetworkSocket);
            continue;
        }

        //creates a file descriptor set and timeout interval
        fd_set writefds, exceptfds;
        struct timeval timeout;

        FD_ZERO(&writefds);
        FD_ZERO(&exceptfds);
        FD_SET(myNetworkSocket, &writefds);
        FD_SET(myNetworkSocket, &exceptfds);
        
        // 对MySQL端口使用更长的超时时间
        timeout.tv_sec = (port == 3306) ? 8 : 5;
        timeout.tv_usec = 0;

        int connectionResponse = select(myNetworkSocket + 1, NULL, &writefds, &exceptfds, &timeout);
        if (connectionResponse > 0) {
            if (FD_ISSET(myNetworkSocket, &exceptfds)) {
                close(myNetworkSocket);
                continue;
            }
            
            if (FD_ISSET(myNetworkSocket, &writefds)) {
                int socketError;
                socklen_t len = sizeof socketError;

                getsockopt(myNetworkSocket, SOL_SOCKET, SO_ERROR, &socketError, &len);

                if (socketError == 0) {
                    close(myNetworkSocket);
                    if (port == 3306 && retry > 0) {
                        std::cout << "MySQL端口3306在第" << retry + 1 << "次重试时连接成功" << std::endl;
                    }
                    return true;
                } else {
                    if (port == 3306) {
                        std::cout << "MySQL端口3306连接失败，错误: " << strerror(socketError) << " (retry " << retry + 1 << ")" << std::endl;
                    }
                    close(myNetworkSocket);
                    continue;
                }
            }
        } else {
            if (port == 3306) {
                std::cout << "MySQL端口3306连接超时 (retry " << retry + 1 << ")" << std::endl;
            }
            close(myNetworkSocket);
            continue;
        }
    }
    
    return false;
}

std::string GetHost() {
  std::string inputHost;

  std::cout << "Hostname/IP: ";
  std::getline(std::cin, inputHost);

  return inputHost;
}

void DisplayOptions() {
  std::cout << std::endl << "OPTIONS:" << std::endl;

  std::vector<std::string> optionDescriptions;

  optionDescriptions.push_back("Scan all ports");
  optionDescriptions.push_back("Scan for a specific port");
  optionDescriptions.push_back("Scan all common ports");

  for (int i = 0; i < optionDescriptions.size(); i++) {
    std::cout << "[" << i << "] " << optionDescriptions.at(i) << std::endl;
  }

  std::cout << std::endl;
}

int GetOption() {
  DisplayOptions();

  std::string optionToReturn;
  std::cout << "Option: ";
  std::getline(std::cin, optionToReturn);

  try {
    return std::stoi(optionToReturn);
  }
  catch (...) {
    return -1;
  }
}

void ThreadTask(std::vector<int>* bufferArg, std::string hostNameArg, int port) {
  // 对MySQL端口进行特殊处理
  if (port == 3306) {
    // 给MySQL端口更多时间，避免连接竞争
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  
  if (TestPortConnection(hostNameArg, port)){
    bufferLock.lock();
    bufferArg->push_back(port);
    bufferLock.unlock();
    
    // 对MySQL端口进行特殊提示
    if (port == 3306) {
      std::cout << "✓ 发现MySQL端口3306开放！" << std::endl;
    }
  } else {
    // 对MySQL端口进行特殊提示
    if (port == 3306) {
      std::cout << "✗ MySQL端口3306关闭或不可达" << std::endl;
    }
  }
}

void ScanAllPorts(std::string hostNameArg) {
  
  std::vector<std::thread*> portTests;

  std::vector<int> buffer;

  int numOfTasks = 1000;

  for (int i = 0; i < 65; i++) {
    for (int j = 1; j < numOfTasks+1; j++) {
      portTests.push_back(new std::thread(ThreadTask, &buffer, hostNameArg, (i*numOfTasks)+j));
    }
    for (int j = 0; j < numOfTasks; j++) {
      portTests.at(j)->join();
    }
    for (int j = 0; j < numOfTasks; j++) {
      delete portTests.at(j);
    }
    portTests = {};
  }

  for (int i = 1; i <= 535; i++) {
    portTests.push_back(new std::thread(ThreadTask, &buffer, hostNameArg, i+65000));
  }
  for (int i = 0; i < 535; i++) {
    portTests.at(i)->join();
  }
  for (int i = 0; i < 535; i++) {
    delete portTests.at(i);
  }

  std::sort(buffer.begin(), buffer.end());

  //print out the list of all the open ports
  if (buffer.size()==0) {
    std::cout << "No open ports" << std::endl;
  }
  else {
    for (int i = 0; i < buffer.size(); i++) {
      std::cout << "Port " << buffer.at(i) << " is open!" << std::endl;
    }
  }

}

void ScanSpecificPort(std::string hostNameArg, int port) {
    //test port number
    if (port<1||port>65535) {
        std::cout << "Invalid port number." << std::endl;
        return;
    }
    
    std::cout << "正在测试端口 " << port << " (" << hostNameArg << ")..." << std::endl;
    
    // 对MySQL端口进行特殊处理
    if (port == 3306) {
        std::cout << "检测到MySQL端口，将进行多次重试测试..." << std::endl;
    }
    
    //test connection
    if (TestPortConnection(hostNameArg, port)){
        std::cout << "✓ Port " << port << " is open!" << std::endl;
        if (port == 3306) {
            std::cout << "MySQL服务正在运行！" << std::endl;
        }
    }
    else {
        std::cout << "✗ Port " << port << " is closed." << std::endl;
        if (port == 3306) {
            std::cout << "MySQL服务未运行或不可达。" << std::endl;
        }
    }
}

void ScanCommonPorts(std::string hostNameArg) {
  std::cout << "开始扫描常用端口 (共" << commonPorts.size() << "个端口)..." << std::endl;
  
  std::vector<int> buffer;
  const int max_concurrent_threads = 150; // 限制并发线程数，避免资源竞争
  
  // 分批处理端口，避免同时创建过多线程
  for (size_t i = 0; i < commonPorts.size(); i += max_concurrent_threads) {
    std::vector<std::thread> portTests;
    
    // 创建当前批次的线程
    size_t end = std::min(i + max_concurrent_threads, commonPorts.size());
    for (size_t j = i; j < end; j++) {
      portTests.push_back(std::thread(ThreadTask, &buffer, hostNameArg, commonPorts.at(j)));
    }
    
    // 等待当前批次完成
    for (auto& thread : portTests) {
      thread.join();
    }
    
    // 显示进度
    std::cout << "已完成 " << end << "/" << commonPorts.size() << " 个端口扫描" << std::endl;
    
    // 在批次之间添加短暂延迟，让系统有时间恢复
    if (end < commonPorts.size()) {
      std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
  }

  std::sort(buffer.begin(), buffer.end());

  //print out the list of all the open ports
  if (buffer.size()==0) {
    std::cout << "No open ports" << std::endl;
  }
  else {
    std::cout << "发现 " << buffer.size() << " 个开放端口:" << std::endl;
    for (int i = 0; i < buffer.size(); i++) {
      std::cout << "Port " << buffer.at(i) << " is open!" << std::endl;
    }
  }
}


std::string get_default_iface() {
    // 自动检测网络接口，而不是硬编码
    struct ifaddrs *ifaddr, *ifa;
    std::string default_iface = "eth0"; // 默认值
    
    if (getifaddrs(&ifaddr) == -1) {
        std::cerr << "警告: 无法获取网络接口信息，使用默认接口 " << default_iface << std::endl;
        return default_iface;
    }
    
    // 查找第一个非回环的IPv4接口
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;
        
        if (ifa->ifa_addr->sa_family == AF_INET) {
            std::string iface_name = ifa->ifa_name;
            
            // 跳过回环接口
            if (iface_name == "lo" || iface_name == "localhost") {
                continue;
            }
            
            // 检查接口是否处于UP状态
            if (!(ifa->ifa_flags & IFF_UP)) {
                continue;
            }
            
            // 优先选择常见的接口名称
            if (iface_name.find("eth") == 0 || 
                iface_name.find("ens") == 0 || 
                iface_name.find("enp") == 0 ||
                iface_name.find("eno") == 0 ||
                iface_name.find("wlan") == 0 ||
                iface_name.find("wlp") == 0) {
                default_iface = iface_name;
                std::cout << "检测到网络接口: " << default_iface << std::endl;
                break;
            }
        }
    }
    
    freeifaddrs(ifaddr);
    
    // 如果没有找到合适的接口，尝试常见的接口名称
    if (default_iface == "eth0") {
        std::vector<std::string> common_interfaces = {"eth0", "ens33", "ens160", "enp0s3", "eno1", "wlan0"};
        for (const auto& iface : common_interfaces) {
            // 检查接口是否存在（通过尝试打开pcap）
            char errbuf[PCAP_ERRBUF_SIZE];
            pcap_t *test_handle = pcap_open_live(iface.c_str(), 65536, 1, 1000, errbuf);
            if (test_handle != NULL) {
                pcap_close(test_handle);
                default_iface = iface;
                std::cout << "使用常见接口: " << default_iface << std::endl;
                break;
            }
        }
    }
    
    return default_iface;
}

// 优化的TCP SYN/FIN扫描实现
void tcp_synfin_scan(const std::string& ip, int port, bool syn) {
    char errbuf[LIBNET_ERRBUF_SIZE] = {0};
    libnet_t *l = libnet_init(LIBNET_RAW4, nullptr, errbuf);
    if (!l) {
        std::cerr << "libnet_init() failed: " << errbuf << std::endl;
        return;
    }
    
    // 生成唯一的源端口，避免冲突
    uint16_t src_port = 40000 + (dis(gen) % 20000);
    uint32_t src_ip = libnet_get_ipaddr4(l);
    uint32_t dst_ip = libnet_name2addr4(l, const_cast<char*>(ip.c_str()), LIBNET_RESOLVE);
    uint8_t flags = syn ? TH_SYN : TH_FIN;
    
    // 构建TCP包
    libnet_ptag_t tcp_tag = libnet_build_tcp(
        src_port, port, dis(gen), dis(gen), flags, 32767, 0, 0, LIBNET_TCP_H, nullptr, 0, l, 0
    );
    
    libnet_ptag_t ip_tag = libnet_build_ipv4(
        LIBNET_IPV4_H + LIBNET_TCP_H, 0, dis(gen), 0, 64, IPPROTO_TCP, 0,
        src_ip, dst_ip, nullptr, 0, l, 0
    );
    
    if (tcp_tag == -1 || ip_tag == -1) {
        std::cerr << "Failed to build packet" << std::endl;
        libnet_destroy(l);
        return;
    }
    
    if (libnet_write(l) < 0) {
        std::cerr << "libnet_write() failed: " << libnet_geterror(l) << std::endl;
        libnet_destroy(l);
        return;
    }
    
    // pcap抓包，优化超时时间
    char pcap_errbuf[PCAP_ERRBUF_SIZE] = {0};
    std::string iface = get_default_iface();
    int timeout = syn ? 1000 : 1500; // SYN扫描用较短超时，FIN扫描用较长超时
    pcap_t *handle = pcap_open_live(iface.c_str(), 65536, 1, timeout, pcap_errbuf);
    if (!handle) {
        std::cerr << "pcap_open_live() failed: " << pcap_errbuf << std::endl;
        libnet_destroy(l);
        return;
    }
    
    // 优化过滤器表达式
    std::string filter_exp = "tcp and src host " + ip + " and dst port " + std::to_string(src_port);
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "pcap filter error" << std::endl;
        pcap_close(handle);
        libnet_destroy(l);
        return;
    }
    
    struct pcap_pkthdr* header;
    const u_char* pkt_data;
    int res = pcap_next_ex(handle, &header, &pkt_data);
    
    if (res == 1) {
        // 解析响应包 - 添加边界检查
        if (header->len < 14 + sizeof(struct ip)) {
            std::cout << "Port " << port << " received invalid packet (too short)\n";
        } else {
            const struct ip* ip_hdr = (struct ip*)(pkt_data + 14);
            if (header->len < 14 + ip_hdr->ip_hl * 4 + sizeof(struct tcphdr)) {
                std::cout << "Port " << port << " received invalid packet (TCP header too short)\n";
            } else {
                const struct tcphdr* tcp_hdr = (struct tcphdr*)(pkt_data + 14 + ip_hdr->ip_hl * 4);
                
                if (syn) {
                    // SYN扫描逻辑
                    if ((tcp_hdr->th_flags & TH_SYN) && (tcp_hdr->th_flags & TH_ACK)) {
                        std::cout << "Port " << port << " is OPEN (SYN+ACK received)\n";
                    } else if (tcp_hdr->th_flags & TH_RST) {
                        std::cout << "Port " << port << " is CLOSED (RST received)\n";
                    } else {
                        std::cout << "Port " << port << " got unknown response\n";
                    }
                } else {
                    // FIN扫描逻辑
                    if (tcp_hdr->th_flags & TH_RST) {
                        std::cout << "Port " << port << " is CLOSED (RST received)\n";
                    } else {
                        std::cout << "Port " << port << " is OPEN|FILTERED (no RST received)\n";
                    }
                }
            }
        }
    } else {
        if (syn) {
            std::cout << "Port " << port << " is FILTERED (no response)\n";
        } else {
            std::cout << "Port " << port << " is OPEN|FILTERED (no response)\n";
        }
    }
    
    pcap_close(handle);
    libnet_destroy(l);
}


// 优化的多端口SYN扫描，返回开放端口列表
std::vector<int> TCPSynScanJson(const std::string& ip, const std::vector<int>& ports) {
    std::vector<int> openPorts;
    
    // 检查是否以root权限运行
    if (geteuid() != 0) {
        std::cerr << "警告: TCP SYN扫描需要root权限，降级为TCP Connect扫描" << std::endl;
        // 降级为TCP Connect扫描
        return tcpConnectScanJson(ip, ports);
    }
    
    std::mutex resultMutex;
    
    // 预初始化libnet和pcap，避免重复初始化
    char errbuf[LIBNET_ERRBUF_SIZE] = {0};
    libnet_t *l = libnet_init(LIBNET_RAW4, nullptr, errbuf);
    if (!l) {
        std::cerr << "libnet_init() failed: " << errbuf << std::endl;
        std::cerr << "降级为TCP Connect扫描" << std::endl;
        return tcpConnectScanJson(ip, ports);
    }
    
    char pcap_errbuf[PCAP_ERRBUF_SIZE] = {0};
    std::string iface = get_interface_for_target(ip);
    if (iface.empty()) {
        std::cerr << "Failed to get interface for target: " << ip << std::endl;
        std::cerr << "降级为TCP Connect扫描" << std::endl;
        libnet_destroy(l);
        return tcpConnectScanJson(ip, ports);
    }
    
    std::cout << "使用网络接口: " << iface << std::endl;
    
    // 使用适中的超时时间，平衡速度和准确性
    pcap_t *handle = pcap_open_live(iface.c_str(), 65536, 1, 1000, pcap_errbuf);
    if (!handle) {
        std::cerr << "pcap_open_live() failed: " << pcap_errbuf << std::endl;
        std::cerr << "降级为TCP Connect扫描" << std::endl;
        libnet_destroy(l);
        return tcpConnectScanJson(ip, ports);
    }
    
    // 预解析目标IP，避免重复解析
    uint32_t dst_ip = libnet_name2addr4(l, const_cast<char*>(ip.c_str()), LIBNET_RESOLVE);
    if (dst_ip == 0) {
        std::cerr << "无法解析目标IP: " << ip << std::endl;
        std::cerr << "降级为TCP Connect扫描" << std::endl;
        pcap_close(handle);
        libnet_destroy(l);
        return tcpConnectScanJson(ip, ports);
    }
    
    // 使用更高效的线程池进行并发扫描
    const int max_threads = 100; // 增加线程数，提高并发度
    std::vector<std::thread> threads;
    
    // 创建端口批次，减少线程创建开销
    const int batch_size = 5; // 每个线程处理5个端口，减少竞争
    
    auto scanBatch = [&](const std::vector<int>& portBatch) {
        // 为每个批次创建独立的libnet和pcap实例，避免竞争条件
        char batch_errbuf[LIBNET_ERRBUF_SIZE] = {0};
        libnet_t *batch_l = libnet_init(LIBNET_RAW4, nullptr, batch_errbuf);
        if (!batch_l) {
            return;
        }
        
        // 为每个批次创建独立的pcap句柄
        char batch_pcap_errbuf[PCAP_ERRBUF_SIZE] = {0};
        pcap_t *batch_handle = pcap_open_live(iface.c_str(), 65536, 1, 1000, batch_pcap_errbuf);
        if (!batch_handle) {
            libnet_destroy(batch_l);
            return;
        }
        
        for (int port : portBatch) {
            // 为每个端口生成唯一的源端口
            uint16_t src_port = 40000 + (dis(gen) % 20000);
            
            uint32_t src_ip = libnet_get_ipaddr4(batch_l);
            
            // 构建TCP SYN包
            libnet_ptag_t tcp_tag = libnet_build_tcp(
                src_port, port, dis(gen), dis(gen), TH_SYN, 32767, 0, 0, LIBNET_TCP_H, nullptr, 0, batch_l, 0
            );
            
            libnet_ptag_t ip_tag = libnet_build_ipv4(
                LIBNET_IPV4_H + LIBNET_TCP_H, 0, dis(gen), 0, 64, IPPROTO_TCP, 0,
                src_ip, dst_ip, nullptr, 0, batch_l, 0
            );
            
            if (tcp_tag == -1 || ip_tag == -1) {
                continue;
            }
            
            // 发送包
            if (libnet_write(batch_l) < 0) {
                continue;
            }
            
            // 对MySQL和SSH端口使用更宽松的过滤器
            std::string filter_exp;
            if (port == 3306 || port == 22) {
                filter_exp = "tcp and src host " + ip + " and (dst port " + std::to_string(src_port) + " or src port " + std::to_string(port) + ")";
            } else {
                filter_exp = "tcp and src host " + ip + " and dst port " + std::to_string(src_port);
            }
            struct bpf_program fp;
            if (pcap_compile(batch_handle, &fp, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1 ||
                pcap_setfilter(batch_handle, &fp) == -1) {
                continue;
            }
            // 对MySQL、SSH和HTTP端口使用更长的超时时间
            struct timeval timeout;
            if (port == 3306 || port == 22 || port == 80) {
                timeout.tv_sec = 2;  // 2秒
                timeout.tv_usec = 0;
            } else {
                timeout.tv_sec = 0;  // 0秒
                timeout.tv_usec = 1200000;  // 1.2秒
            }
            
            // 等待响应，使用适中的超时时间
            struct pcap_pkthdr* header;
            const u_char* pkt_data;
            
            // 使用select进行超时控制
            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(pcap_get_selectable_fd(batch_handle), &readfds);
            
            int select_result = select(pcap_get_selectable_fd(batch_handle) + 1, &readfds, NULL, NULL, &timeout);
            
            if (select_result > 0 && FD_ISSET(pcap_get_selectable_fd(batch_handle), &readfds)) {
                int res = pcap_next_ex(batch_handle, &header, &pkt_data);
                
                if (res == 1) {
                    // 解析响应包 - 添加边界检查
                    if (header->len >= 14 + sizeof(struct ip)) {
                        const struct ip* ip_hdr = (struct ip*)(pkt_data + 14);
                        if (header->len >= 14 + ip_hdr->ip_hl * 4 + sizeof(struct tcphdr)) {
                            const struct tcphdr* tcp_hdr = (struct tcphdr*)(pkt_data + 14 + ip_hdr->ip_hl * 4);
                            
                            // 检查是否为SYN+ACK响应
                            if ((tcp_hdr->th_flags & TH_SYN) && (tcp_hdr->th_flags & TH_ACK)) {
                                std::lock_guard<std::mutex> lock(resultMutex);
                                openPorts.push_back(port);
                                std::cout << "发现开放端口: " << port << " (SYN+ACK)" << std::endl;
                            }
                        }
                    }
                }
            }
            
            // 清理当前包，准备下一个
            libnet_clear_packet(batch_l);
        }
        
        // 清理批次资源
        pcap_close(batch_handle);
        libnet_destroy(batch_l);
    };
    
    // 分批处理端口
    for (size_t i = 0; i < ports.size(); i += batch_size) {
        threads.clear();
        size_t end = std::min(i + batch_size, ports.size());
        
        std::cout << "扫描端口 " << i + 1 << " 到 " << end << " (共 " << ports.size() << " 个)" << std::endl;
        
        // 创建当前批次的端口列表
        std::vector<int> portBatch(ports.begin() + i, ports.begin() + end);
        
        // 创建线程处理当前批次
        threads.emplace_back(scanBatch, portBatch);
        
        // 等待当前批次完成
        for (auto& thread : threads) {
            thread.join();
        }
        
        // 在批次之间添加短暂延迟，让系统有时间恢复
        if (end < ports.size()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
    }
    
    // 清理资源
    pcap_close(handle);
    libnet_destroy(l);
    
    std::sort(openPorts.begin(), openPorts.end());
    std::cout << "SYN扫描完成，发现 " << openPorts.size() << " 个开放端口" << std::endl;
    return openPorts;
}

// 新增：TCP Connect扫描的JSON版本
std::vector<int> tcpConnectScanJson(const std::string& ip, const std::vector<int>& ports) {
    std::vector<int> openPorts;
    std::mutex resultMutex;
    
    std::cout << "使用TCP Connect扫描模式" << std::endl;
    
    // 使用线程池进行并发扫描
    const int max_threads = 100;
    std::vector<std::thread> threads;
    
    auto scanPort = [&](int port) {
        if (TestPortConnection(ip, port)) {
            std::lock_guard<std::mutex> lock(resultMutex);
            openPorts.push_back(port);
            std::cout << "发现开放端口: " << port << " (Connect)" << std::endl;
        }
    };
    
    // 分批处理端口
    for (size_t i = 0; i < ports.size(); i += max_threads) {
        threads.clear();
        size_t end = std::min(i + max_threads, ports.size());
        
        std::cout << "扫描端口 " << i + 1 << " 到 " << end << " (共 " << ports.size() << " 个)" << std::endl;
        
        for (size_t j = i; j < end; j++) {
            threads.emplace_back(scanPort, ports[j]);
        }
        
        for (auto& thread : threads) {
            thread.join();
        }
        
        // 在批次之间添加短暂延迟
        if (end < ports.size()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
    }
    
    std::sort(openPorts.begin(), openPorts.end());
    std::cout << "Connect扫描完成，发现 " << openPorts.size() << " 个开放端口" << std::endl;
    return openPorts;
}

// 优化的多端口FIN扫描，返回开放端口列表
std::vector<int> TCPFinScanJson(const std::string& ip, const std::vector<int>& ports) {
    std::vector<int> openPorts;
    std::vector<int> filteredPorts; // 新增：被过滤的端口列表
    
    // 检查是否以root权限运行
    if (geteuid() != 0) {
        std::cerr << "警告: TCP FIN扫描需要root权限，降级为TCP Connect扫描" << std::endl;
        // 降级为TCP Connect扫描
        return tcpConnectScanJson(ip, ports);
    }
    
    std::mutex resultMutex;
    
    // 预初始化libnet和pcap，避免重复初始化
    char errbuf[LIBNET_ERRBUF_SIZE] = {0};
    libnet_t *l = libnet_init(LIBNET_RAW4, nullptr, errbuf);
    if (!l) {
        std::cerr << "libnet_init() failed: " << errbuf << std::endl;
        std::cerr << "降级为TCP Connect扫描" << std::endl;
        return tcpConnectScanJson(ip, ports);
    }
    
    char pcap_errbuf[PCAP_ERRBUF_SIZE] = {0};
    std::string iface = get_default_iface();
    if (iface.empty()) {
        std::cerr << "Failed to get default interface" << std::endl;
        std::cerr << "降级为TCP Connect扫描" << std::endl;
        libnet_destroy(l);
        return tcpConnectScanJson(ip, ports);
    }
    
    std::cout << "使用网络接口: " << iface << std::endl;
    
    // 使用适中的超时时间，平衡速度和准确性
    pcap_t *handle = pcap_open_live(iface.c_str(), 65536, 1, 1200, pcap_errbuf);
    if (!handle) {
        std::cerr << "pcap_open_live() failed: " << pcap_errbuf << std::endl;
        std::cerr << "降级为TCP Connect扫描" << std::endl;
        libnet_destroy(l);
        return tcpConnectScanJson(ip, ports);
    }
    
    // 预解析目标IP，避免重复解析
    uint32_t dst_ip = libnet_name2addr4(l, const_cast<char*>(ip.c_str()), LIBNET_RESOLVE);
    if (dst_ip == 0) {
        std::cerr << "无法解析目标IP: " << ip << std::endl;
        std::cerr << "降级为TCP Connect扫描" << std::endl;
        pcap_close(handle);
        libnet_destroy(l);
        return tcpConnectScanJson(ip, ports);
    }
    
    // 使用更高效的线程池进行并发扫描
    const int max_threads = 80; // FIN扫描使用较少的线程，因为需要等待响应
    std::vector<std::thread> threads;
    
    // 创建端口批次，减少线程创建开销
    const int batch_size = 4; // 每个线程处理4个端口，减少竞争
    
    auto scanBatch = [&](const std::vector<int>& portBatch) {
        // 为每个批次创建独立的libnet和pcap实例，避免竞争条件
        char batch_errbuf[LIBNET_ERRBUF_SIZE] = {0};
        libnet_t *batch_l = libnet_init(LIBNET_RAW4, nullptr, batch_errbuf);
        if (!batch_l) {
            return;
        }
        
        // 为每个批次创建独立的pcap句柄
        char batch_pcap_errbuf[PCAP_ERRBUF_SIZE] = {0};
        pcap_t *batch_handle = pcap_open_live(iface.c_str(), 65536, 1, 1200, batch_pcap_errbuf);
        if (!batch_handle) {
            libnet_destroy(batch_l);
            return;
        }
        
        for (int port : portBatch) {
            // 调试输出，确认端口被扫描
            std::cout << "[DEBUG] 正在FIN扫描端口: " << port << std::endl;
            // 为每个端口生成唯一的源端口
            uint16_t src_port = 40000 + (dis(gen) % 20000);
            
            uint32_t src_ip = libnet_get_ipaddr4(batch_l);
            
            // 构建TCP FIN包
            libnet_ptag_t tcp_tag = libnet_build_tcp(
                src_port, port, dis(gen), dis(gen), TH_FIN, 32767, 0, 0, LIBNET_TCP_H, nullptr, 0, batch_l, 0
            );
            
            libnet_ptag_t ip_tag = libnet_build_ipv4(
                LIBNET_IPV4_H + LIBNET_TCP_H, 0, dis(gen), 0, 64, IPPROTO_TCP, 0,
                src_ip, dst_ip, nullptr, 0, batch_l, 0
            );
            
            if (tcp_tag == -1 || ip_tag == -1) {
                continue;
            }
            
            // 发送包
            if (libnet_write(batch_l) < 0) {
                continue;
            }
            
            // 设置pcap过滤器
            std::string filter_exp = "tcp and src host " + ip + " and dst port " + std::to_string(src_port);
            struct bpf_program fp;
            if (pcap_compile(batch_handle, &fp, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1 ||
                pcap_setfilter(batch_handle, &fp) == -1) {
                continue;
            }
            
            // 设置超时时间：80和3306端口都用2秒，其它端口0.8秒
            struct timeval timeout;
            if (port == 80 || port == 3306) {
                timeout.tv_sec = 2;
                timeout.tv_usec = 0;
            } else {
                timeout.tv_sec = 0;
                timeout.tv_usec = 800000;
            }
            
            // 使用select进行超时控制
            fd_set readfds;
            FD_ZERO(&readfds);
            FD_SET(pcap_get_selectable_fd(batch_handle), &readfds);
            
            int select_result = select(pcap_get_selectable_fd(batch_handle) + 1, &readfds, NULL, NULL, &timeout);
            
            if (select_result > 0 && FD_ISSET(pcap_get_selectable_fd(batch_handle), &readfds)) {
                struct pcap_pkthdr* header;
                const u_char* pkt_data;
                int res = pcap_next_ex(batch_handle, &header, &pkt_data);
                bool is_rst = false;
                if (res == 1) {
                    // 有响应，检查是否为RST - 添加边界检查
                    if (header->len >= 14 + sizeof(struct ip)) {
                        const struct ip* ip_hdr = (struct ip*)(pkt_data + 14);
                        if (header->len >= 14 + ip_hdr->ip_hl * 4 + sizeof(struct tcphdr)) {
                            const struct tcphdr* tcp_hdr = (struct tcphdr*)(pkt_data + 14 + ip_hdr->ip_hl * 4);
                            // 检查是否为RST包
                            if (tcp_hdr->th_flags & TH_RST) {
                                is_rst = true;
                                std::cout << "端口 " << port << " 关闭 (FIN RST)" << std::endl;
                            }
                        }
                    }
                }
                if (!is_rst) {
                    // 没有收到RST，判定为开放|过滤
                    std::lock_guard<std::mutex> lock(resultMutex);
                    openPorts.push_back(port);
                    std::cout << "端口 " << port << " 开放|过滤 (FIN无响应或非RST响应)" << std::endl;
                }
            } else {
                // 超时或没有响应，判定为开放|过滤
                std::lock_guard<std::mutex> lock(resultMutex);
                openPorts.push_back(port);
                std::cout << "端口 " << port << " 开放|过滤 (FIN无响应)" << std::endl;
            }
            
            // 清理当前包，准备下一个
            libnet_clear_packet(batch_l);
        }
        
        // 清理批次资源
        pcap_close(batch_handle);
        libnet_destroy(batch_l);
    };
    
    // 分批处理端口
    for (size_t i = 0; i < ports.size(); i += batch_size) {
        threads.clear();
        size_t end = std::min(i + batch_size, ports.size());
        
        std::cout << "扫描端口 " << i + 1 << " 到 " << end << " (共 " << ports.size() << " 个)" << std::endl;
        
        // 创建当前批次的端口列表
        std::vector<int> portBatch(ports.begin() + i, ports.begin() + end);
        
        // 创建线程处理当前批次
        threads.emplace_back(scanBatch, portBatch);
        
        // 等待当前批次完成
        for (auto& thread : threads) {
            thread.join();
        }
        
        // 在批次之间添加短暂延迟，让系统有时间恢复
        if (end < ports.size()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    }
    
    // 清理资源
    pcap_close(handle);
    libnet_destroy(l);
    
    std::sort(openPorts.begin(), openPorts.end());
    std::cout << "FIN扫描完成，发现 " << openPorts.size() << " 个开放|过滤端口" << std::endl;
    return openPorts;
}


// UDP端口扫描实现
void UDPScan(const std::string& ip, int option) {
    std::vector<int> ports;
    if (option == 0) {
        for (int p = 1; p <= 1024; ++p) ports.push_back(p);
    } else if (option == 1) {
        int port;
        std::cout << "Port #: ";
        std::cin >> port;
        ports.push_back(port);
    } else if (option == 2) {
        ports = commonPorts;
    } else {
        std::cout << "Invalid option.\n";
        return;
    }
    std::cout << "[UDP] 扫描 " << ip << " ...\n";
    for (int port : ports) {
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            std::cerr << "Socket creation failed for port " << port << std::endl;
            continue;
        }
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

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
            std::cout << "Port " << port << " is open|filtered (no response)" << std::endl;
        } else {
            std::cout << "Port " << port << " is open (response received)" << std::endl;
        }
        close(sock);
    }
}


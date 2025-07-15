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
#include <bits/stdc++.h>
#include <libnet.h>
#include <pcap.h>
#include <ifaddrs.h>
#include "../ICMP/network.h"
#include <netinet/udp.h>  // 包含UDP头部定义
#include <netinet/ip_icmp.h>
std::mutex bufferLock;


std::vector<int> commonPorts = {7, //Echo
    19, //Chargen
    20, //FTP Data Transfer
    21, //FTP Command Control
    22, //FTPS/SSH
    23, //Telnet
    25, //SMTP
    26, //SMTP
    42, //WINS Replication
    43, //WHOIS
    49, //TACACS
    53, //DNS service
    67, //DHCP
    68, //DHCP
    69, //TFTP
    70, //Gopher
    79, //Finger
    80, //HTTP
    88, //Kerberos
    102, //MS Exchange
    110, //POP3
    113, //Ident
    119, //NNTP (Usenet)
    123, //NTP
    135, //Microsoft RPC
    137, //NetBIOS
    138, //NetBIOS
    139, //NetBIOS
    143, //IMAP
    161, //SNMP
    162, //SNMP
    177, //XDMCP
    179, //BGP
    194, //IRC
    201, //AppleTalk
    264, //BGMP
    318, //TSP
    381, //HP Openview
    382, //HP Openview
    383, //HP Openview
    389, //LDAP
    411, //Direct Connect
    412, //Direct Connect
    443, //HTTPS
    445, //Microsoft DS
    464, //Kerberos
    465, //SMTP over SSL
    497, //Retrospect
    500, //ISAKMP
    512, //rexec
    513, //rlogin
    514, //syslog
    515, //LPD/LPR
    520, //RIP
    521, //RIPng (IPv6)
    540, //UUCP
    554, //RTSP
    546, //DHCPv6
    547, //DHCPv6
    560, //rmonitor
    563, //NNTP over SSL
    587, //SMTP SSL
    591, //FileMaker
    593, //Microsoft DCOM
    631, //Internet Printing Protocol
    636, //LDAP over SSL
    639, //MSDP (PIM)
    646, //LDP (MPLS)
    691, //MS Exchange
    860, //iSCSI
    873, //rsync
    902, //VMware Server
    989, //FTP over SSL
    990, //FTP over SSL
    993, //IMAP SSL
    995, //POP3 SSL
    1025, //Microsoft RPC
    1026, //Windows Messenger
    1027, //Windows Messenger
    1028, //Windows Messenger
    1029, //Windows Messenger
    1080, //SOCKS Proxy
    1080, //MyDoom
    1194, //OpenVPN
    1214, //Kazaa
    1241, //Nessus
    1311, //Dell OpenManage
    1337, //WASTE
    1433, //Microsoft SQL
    1434, //Microsoft SQL
    1512, //WINS
    1589, //Cisco VQP
    1701, //L2TP
    1723, //MS PPTP
    1725, //Steam
    1741, //CiscoWorks 2000
    1755, //MS Media Server
    1812, //RADIUS
    1813, //RADIUS
    1863, //MSN
    1985, //Cisco HSRP
    2000, //Cisco SCCP
    2002, //Cisco ACS
    2049, //NFS
    2077, //WebDAV/WebDisk
    2078, //WebDAV/WebDisk SSL
    2082, //cPanel
    2083, //cPanel SSL
    2086, //WHM
    2087, //WHM SSL
    2095, //Webmail
    2096, //Webmail SSL
    2100, //Oracle XDB
    2222, //DirectAdmin
    2302, //Halo
    2483, //Oracle DB
    2484, //Oracle DB
    2745, //Bagle.H
    2967, //Symantec AV
    3050, //Interbase DB
    3074, //XBOX Live
    3124, //HTTP Proxy
    3127, //MyDoom
    3128, //HTTP Proxy
    3222, //GLBP
    3260, //iSCSI Target
    3306, //MySQL
    3389, //Terminal Server
    3689, //iTunes
    3690, //Subversion
    3724, //World of Warcraft
    3784, //Ventrilo
    3785, //Ventrilo
    4333, //mSQL
    4444, //Blaster
    4664, //Google Desktop
    4672, //eMule
    4899, //- Radmin
    5000, //UPnP
    5001, //Slingbox
    5001, //iperf
    5004, //RTP
    5005, //RTP
    5050, //Yahoo! Messenger
    5060, //SIP
    5190, //AIM/ICQ
    5222, //XMPP/Jabber
    5223, //XMPP/Jabber
    5432, //PostgreSQL
    5500, //VNC Server
    5554, //Sasser
    5631, //pcAnywhere
    5632, //pcAnywhere
    5800, //VNC over HTTP
    5900, //VNC Server
    5901, //VNC Server
    5902, //VNC Server
    5903, //VNC Server
    5904, //VNC Server
    5905, //VNC Server
    5906, //VNC Server
    5907, //VNC Server
    5908, //VNC Server
    5909, //VNC Server
    5910, //VNC Server
    5911, //VNC Server
    5912, //VNC Server
    5913, //VNC Server
    5914, //VNC Server
    5915, //VNC Server
    5916, //VNC Server
    5917, //VNC Server
    5918, //VNC Server
    5919, //VNC Server
    5920, //VNC Server
    5921, //VNC Server
    5922, //VNC Server
    5923, //VNC Server
    5924, //VNC Server
    5925, //VNC Server
    5926, //VNC Server
    5927, //VNC Server
    5928, //VNC Server
    5929, //VNC Server
    5930, //VNC Server
    5931, //VNC Server
    5932, //VNC Server
    5933, //VNC Server
    5934, //VNC Server
    5935, //VNC Server
    5936, //VNC Server
    5937, //VNC Server
    5938, //VNC Server
    5939, //VNC Server
    5940, //VNC Server
    5941, //VNC Server
    5942, //VNC Server
    5943, //VNC Server
    5944, //VNC Server
    5945, //VNC Server
    5946, //VNC Server
    5947, //VNC Server
    5948, //VNC Server
    5949, //VNC Server
    5950, //VNC Server
    5951, //VNC Server
    5952, //VNC Server
    5953, //VNC Server
    5954, //VNC Server
    5955, //VNC Server
    5956, //VNC Server
    5957, //VNC Server
    5958, //VNC Server
    5959, //VNC Server
    5960, //VNC Server
    5961, //VNC Server
    5962, //VNC Server
    5963, //VNC Server
    5964, //VNC Server
    5965, //VNC Server
    5966, //VNC Server
    5967, //VNC Server
    5968, //VNC Server
    5969, //VNC Server
    5970, //VNC Server
    5971, //VNC Server
    5972, //VNC Server
    5973, //VNC Server
    5974, //VNC Server
    5975, //VNC Server
    5976, //VNC Server
    5977, //VNC Server
    5978, //VNC Server
    5979, //VNC Server
    5980, //VNC Server
    5981, //VNC Server
    5982, //VNC Server
    5983, //VNC Server
    5984, //VNC Server
    5985, //VNC Server
    5986, //VNC Server
    5987, //VNC Server
    5988, //VNC Server
    5989, //VNC Server
    5990, //VNC Server
    5991, //VNC Server
    5992, //VNC Server
    5993, //VNC Server
    5994, //VNC Server
    5995, //VNC Server
    5996, //VNC Server
    5997, //VNC Server
    5998, //VNC Server
    5999, //VNC Server
    6000, //X11
    6001, //X11
    6112, //Battle.net
    6129, //DameWare
    6257, //WinMX
    6346, //Gnutella
    6347, //Gnutella
    6500, //GameSpy Arcade
    6566, //SANE
    6588, //AnalogX
    6665, //IRC
    6666, //IRC
    6667, //IRC
    6668, //IRC
    6669, //IRC
    6679, //IRC over SSL
    6697, //IRC over SSL
    6699, //Napster
    6881, //BitTorrent
    6891, //Windows Live
    6892, //Windows Live
    6893, //Windows Live
    6894, //Windows Live
    6895, //Windows Live
    6896, //Windows Live
    6897, //Windows Live
    6898, //Windows Live
    6899, //Windows Live
    6900, //Windows Live
    6901, //Windows Live
    6970, //Quicktime
    7212, //GhostSurf
    7648, //CU-SeeMe
    7649, //CU-SeeMe
    8000, //Internet Radio
    8080, //HTTP Proxy
    8086, //Kaspersky AV
    8087, //Kaspersky AV
    8118, //Privoxy
    8200, //VMware Server
    8500, //Adobe ColdFusion
    8767, //TeamSpeak
    8866, //Bagle.B
    9100, //HP JetDirect
    9101, //Bacula
    9102, //Bacula
    9103, //Bacula
    9119, //MXit
    9800, //WebDAV
    9898, //Dabber
    9988, //Rbot/Spybot
    9999, //Urchin
    10000, //Webmin
    10000, //BackupExec
    10113, //NetIQ
    10114, //NetIQ
    10115, //NetIQ
    10116, //NetIQ
    11371, //OpenPGP
    12035, //Second Life
    12036, //Second Life
    12345, //NetBus
    13720, //NetBackup
    13721, //NetBackup
    14567, //Battlefield
    15118, //Dipnet/Oddbob
    19226, //AdminSecure
    19638, //Ensim
    20000, //Usermin
    24800, //Synergy
    25999, //Xfire
    27015, //Half-Life
    27017, //MongoDB
    27374, //Sub7
    28960, //Call of Duty
    31337}; //Back Orifice



bool TestPortConnection(const std::string& ip_addr, int port) {
    struct sockaddr_in address;
    int myNetworkSocket = -1;
    
    // 只接受已解析的IP字符串，不再做DNS解析
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = inet_addr(ip_addr.c_str());
    address.sin_port = htons(port);

    myNetworkSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (myNetworkSocket == -1) {
        std::cout << "Socket creation failed on port " << port << std::endl;
        return false;
    }
    
    // 设置socket选项
    int opt = 1;
    setsockopt(myNetworkSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    // 设置为非阻塞
    fcntl(myNetworkSocket, F_SETFL, O_NONBLOCK);
    
    int ret = connect(myNetworkSocket, (struct sockaddr *)&address, sizeof(address));
    if (ret == 0) {
        // 立即连接成功，端口开放
        close(myNetworkSocket);
        return true;
    } else if (errno != EINPROGRESS) {
        // 连接出错且不是正在进行中，端口关闭
        close(myNetworkSocket);
        return false;
    }
    
    // 使用select等待连接完成
    fd_set writefds, exceptfds;
    FD_ZERO(&writefds);
    FD_ZERO(&exceptfds);
    FD_SET(myNetworkSocket, &writefds);
    FD_SET(myNetworkSocket, &exceptfds);
    
    struct timeval timeout;
    timeout.tv_sec = 5;  // 增加超时时间到5秒
    timeout.tv_usec = 0;
    
    int sel = select(myNetworkSocket + 1, NULL, &writefds, &exceptfds, &timeout);
    
    if (sel > 0) {
        if (FD_ISSET(myNetworkSocket, &exceptfds)) {
            // 连接出现异常
            close(myNetworkSocket);
            return false;
        }
        
        if (FD_ISSET(myNetworkSocket, &writefds)) {
            int so_error = 0;
            socklen_t len = sizeof(so_error);
            getsockopt(myNetworkSocket, SOL_SOCKET, SO_ERROR, &so_error, &len);
            close(myNetworkSocket);
            
            if (so_error == 0) {
                return true; // 端口开放
            } else {
                return false; // 端口关闭
            }
        }
    }
    
    // select超时或出错
    close(myNetworkSocket);
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

void ThreadTask(std::vector<int>* bufferArg, const std::string& ip_addr, int port) {
  // 对MySQL端口进行特殊处理
  if (port == 3306) {
    // 给MySQL端口更多时间，避免连接竞争
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  
  if (TestPortConnection(ip_addr, port)){
    bufferLock.lock();
    bufferArg->push_back(port);
    bufferLock.unlock();
    
    // 对MySQL端口进行特殊提示
    // if (port == 3306) {
    //   std::cout << "✓ 发现MySQL端口3306开放！" << std::endl;
    // }
  } else {
    // 对MySQL端口进行特殊提示
    // if (port == 3306) {
    //   std::cout << "✗ MySQL端口3306关闭或不可达" << std::endl;
    // }
  }
}

void ScanAllPorts(std::string hostNameArg) {
  // 先做一次域名解析
  std::string ip_addr = hostNameArg;
  if (hostNameArg.find_first_not_of("0123456789.") != std::string::npos) {
    ip_addr = dns_lookup(hostNameArg);
    if (ip_addr.empty()) {
      std::cerr << "DNS lookup failed for " << hostNameArg << std::endl;
      std::cout << "No open ports" << std::endl;
      return;
    }
  }
  std::vector<std::thread*> portTests;
  std::vector<int> buffer;
  int numOfTasks = 1000;
  for (int i = 0; i < 65; i++) {
    for (int j = 1; j < numOfTasks+1; j++) {
      portTests.push_back(new std::thread(ThreadTask, &buffer, ip_addr, (i*numOfTasks)+j));
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
    portTests.push_back(new std::thread(ThreadTask, &buffer, ip_addr, i+65000));
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
    // 先做一次域名解析
    std::string ip_addr = hostNameArg;
    if (hostNameArg.find_first_not_of("0123456789.") != std::string::npos) {
        ip_addr = dns_lookup(hostNameArg);
        if (ip_addr.empty()) {
            std::cerr << "DNS lookup failed for " << hostNameArg << std::endl;
            std::cout << "Port " << port << " is closed." << std::endl;
            return;
        }
    }
    
    std::cout << "正在测试端口 " << port << " (" << ip_addr << ")..." << std::endl;
    
    //test connection
    if (TestPortConnection(ip_addr, port)){
        std::cout << "✓ Port " << port << " is open!" << std::endl;
    }
    else {
        std::cout << "✗ Port " << port << " is closed." << std::endl;
    }
}

void ScanCommonPorts(std::string hostNameArg) {
  // 先做一次域名解析
  std::string ip_addr = hostNameArg;
  if (hostNameArg.find_first_not_of("0123456789.") != std::string::npos) {
    ip_addr = dns_lookup(hostNameArg);
    if (ip_addr.empty()) {
      std::cerr << "DNS lookup failed for " << hostNameArg << std::endl;
      std::cout << "No open ports" << std::endl;
      return;
    }
  }
  
  std::cout << "开始扫描常见端口 (共" << commonPorts.size() << "个端口)..." << std::endl;
  
  std::vector<int> buffer;
  const int max_concurrent_threads = 80; // 限制并发线程数，避免资源竞争
  
  // 分批处理端口，避免同时创建过多线程
  for (size_t i = 0; i < commonPorts.size(); i += max_concurrent_threads) {
    std::vector<std::thread> portTests;
    
    // 创建当前批次的线程
    size_t end = std::min(i + max_concurrent_threads, commonPorts.size());
    for (size_t j = i; j < end; j++) {
      portTests.push_back(std::thread(ThreadTask, &buffer, ip_addr, commonPorts.at(j)));
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
    struct ifaddrs *ifap, *ifa;
    struct sockaddr_in *sa;
    char addr[INET_ADDRSTRLEN];
    std::string iface;
    std::string lo_iface; // 保存回环接口名称

    if (getifaddrs(&ifap) == -1) {
        perror("getifaddrs");
        return "eth0"; // 返回默认接口
    }

    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
            sa = (struct sockaddr_in *)ifa->ifa_addr;
            inet_ntop(AF_INET, &sa->sin_addr, addr, INET_ADDRSTRLEN);
            
            // 保存回环接口名称
            if (strcmp(addr, "127.0.0.1") == 0) {
                lo_iface = ifa->ifa_name;
                continue;
            }
            
            // 检查接口是否处于UP状态
            if (!(ifa->ifa_flags & IFF_UP)) {
                continue;
            }
            
            // 取第一个非回环的接口
            if (iface.empty()) {
                iface = ifa->ifa_name;
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
    
    // 如果仍然没有找到，返回lo接口
    if (iface.empty() && !lo_iface.empty()) {
        iface = lo_iface;
    }
    
    return iface;
}

// 根据目标IP智能选择接口
std::string get_interface_for_target(const std::string& target_ip) {
    std::cout << "[DEBUG] 目标IP: " << target_ip << std::endl;
    
    // 如果目标是本地主机，优先使用lo接口
    if (target_ip == "127.0.0.1" || target_ip == "localhost") {
        std::cout << "[DEBUG] 检测到本地主机，使用lo接口" << std::endl;
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
                    std::cout << "[DEBUG] 找到lo接口: " << lo_iface << std::endl;
                    return lo_iface;
                }
            }
        }
        freeifaddrs(ifap);
    }
    
    // 对于其他IP，使用非回环接口
    std::cout << "[DEBUG] 检测到远程主机，使用非回环接口" << std::endl;
    struct ifaddrs *ifap, *ifa;
    std::string iface;
    
    if (getifaddrs(&ifap) == -1) {
        std::cout << "[DEBUG] getifaddrs失败，返回默认接口eth0" << std::endl;
        return "eth0"; // 返回默认接口
    }
    
    for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET) {
            struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
            char addr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &sa->sin_addr, addr, INET_ADDRSTRLEN);
            
            std::cout << "[DEBUG] 发现接口: " << ifa->ifa_name << " IP: " << addr << " 状态: " << (ifa->ifa_flags & IFF_UP ? "UP" : "DOWN") << std::endl;
            
            // 排除回环接口，只选择非回环接口
            if (strcmp(ifa->ifa_name, "lo") == 0 || strcmp(addr, "127.0.0.1") == 0) {
                std::cout << "[DEBUG] 跳过回环接口: " << ifa->ifa_name << std::endl;
                continue;
            }
            
            // 检查接口是否处于UP状态
            if (!(ifa->ifa_flags & IFF_UP)) {
                std::cout << "[DEBUG] 跳过DOWN状态接口: " << ifa->ifa_name << std::endl;
                continue;
            }
            
            // 取第一个非回环的接口
            if (iface.empty()) {
                iface = ifa->ifa_name;
                std::cout << "[DEBUG] 选择接口: " << iface << std::endl;
                break;
            }
        }
    }
    
    freeifaddrs(ifap);
    
    // 如果没有找到非回环接口，尝试常见的接口名称
    if (iface.empty()) {
        std::cout << "[DEBUG] 未找到合适的接口，尝试常见接口名称" << std::endl;
        std::vector<std::string> common_interfaces = {"eth0", "ens33", "ens160", "enp0s3", "eno1", "wlan0"};
        for (const auto& common_iface : common_interfaces) {
            // 检查接口是否存在（通过尝试打开pcap）
            char errbuf[PCAP_ERRBUF_SIZE];
            pcap_t *test_handle = pcap_open_live(common_iface.c_str(), 65536, 1, 1000, errbuf);
            if (test_handle != NULL) {
                pcap_close(test_handle);
                iface = common_iface;
                std::cout << "[DEBUG] 使用常见接口: " << iface << std::endl;
                break;
            }
        }
    }
    
    std::cout << "[DEBUG] 最终选择的接口: " << iface << std::endl;
    return iface;
}


// TCP SYN 扫描实现
void tcp_syn_scan(const std::string& ip, int port) {
    std::cout << "[SYN] Scanning port " << port << "..." << std::endl;
    char pcap_errbuf[PCAP_ERRBUF_SIZE] = {0};
    std::string iface = get_interface_for_target(ip);
    std::cout << "抓包网卡: " << iface << " 目标IP: " << ip << std::endl;
    pcap_t *handle = pcap_open_live(iface.c_str(), 65536, 1, 2000, pcap_errbuf);
    if (!handle) {
        std::cerr << "pcap_open_live() failed: " << pcap_errbuf << std::endl;
        return;
    }
    std::string filter_exp = "tcp and src host " + ip;
    std::cout << "pcap filter: " << filter_exp << std::endl;
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "pcap filter error" << std::endl;
        pcap_close(handle);
        return;
    }

    std::atomic<bool> got_result(false);
    std::string result_msg;
    uint16_t src_port = 40000 + (rand() % 10000);
    uint32_t seq = libnet_get_prand(LIBNET_PRu32);
    uint32_t src_ip, dst_ip;
    uint8_t flags = TH_SYN;

    std::thread sniffer([&]() {
        auto start = std::chrono::steady_clock::now();
        while (!got_result && std::chrono::steady_clock::now() - start < std::chrono::seconds(2)) {
            struct pcap_pkthdr* header;
            const u_char* pkt_data;
            int res = pcap_next_ex(handle, &header, &pkt_data);
            if (res == 1) {
                const struct ip* ip_hdr = (struct ip*)(pkt_data + 14);
                const struct tcphdr* tcp_hdr = (struct tcphdr*)(pkt_data + 14 + ip_hdr->ip_hl * 4);
                if (ntohs(tcp_hdr->th_dport) == src_port && ntohs(tcp_hdr->th_sport) == port) {
                    if ((tcp_hdr->th_flags & TH_SYN) && (tcp_hdr->th_flags & TH_ACK)) {
                        result_msg = "Port " + std::to_string(port) + " is OPEN (SYN+ACK received)";
                        got_result = true;
                        break;
                    } else if (tcp_hdr->th_flags & TH_RST) {
                        result_msg = "Port " + std::to_string(port) + " is CLOSED (RST received)";
                        got_result = true;
                        break;
                    } else {
                        result_msg = "Port " + std::to_string(port) + " got unknown response";
                        got_result = true;
                        break;
                    }
                }
            }
        }
    });

    char errbuf[LIBNET_ERRBUF_SIZE] = {0};
    libnet_t *l = libnet_init(LIBNET_RAW4, nullptr, errbuf);
    if (!l) {
        std::cerr << "libnet_init() failed: " << errbuf << std::endl;
        got_result = true;
        sniffer.join();
        pcap_close(handle);
        return;
    }
    src_ip = libnet_get_ipaddr4(l);
    dst_ip = libnet_name2addr4(l, const_cast<char*>(ip.c_str()), LIBNET_RESOLVE);
    libnet_build_tcp(
        src_port, port, seq, 0, flags, 32767, 0, 0, LIBNET_TCP_H, nullptr, 0, l, 0
    );
    libnet_build_ipv4(
        LIBNET_IPV4_H + LIBNET_TCP_H, 0, libnet_get_prand(LIBNET_PRu16), 0, 64, IPPROTO_TCP, 0,
        src_ip, dst_ip, nullptr, 0, l, 0
    );
    if (libnet_write(l) < 0) {
        std::cerr << "libnet_write() failed: " << libnet_geterror(l) << std::endl;
        got_result = true;
        sniffer.join();
        pcap_close(handle);
        libnet_destroy(l);
        return;
    }

    sniffer.join();
    if (got_result) {
        std::cout << result_msg << std::endl;
    } else {
        std::cout << "Port " << port << " no response (timeout)" << std::endl;
    }
    pcap_close(handle);
    libnet_destroy(l);
}

// TCP FIN 扫描实现
void tcp_fin_scan(const std::string& ip, int port) {
    std::cout << "[FIN] Scanning port " << port << "..." << std::endl;
    char pcap_errbuf[PCAP_ERRBUF_SIZE] = {0};
    std::string iface = get_interface_for_target(ip);
    std::cout << "抓包网卡: " << iface << " 目标IP: " << ip << std::endl;
    pcap_t *handle = pcap_open_live(iface.c_str(), 65536, 1, 200, pcap_errbuf);
    if (!handle) {
        std::cerr << "pcap_open_live() failed: " << pcap_errbuf << std::endl;
        return;
    }
    // std::string filter_exp = "tcp and src host " + ip;
    // std::cout << "pcap filter: " << filter_exp << std::endl;
    // struct bpf_program fp;
    // if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1 ||
    //     pcap_setfilter(handle, &fp) == -1) {
    //     std::cerr << "pcap filter error" << std::endl;
    //     pcap_close(handle);
    //     return;
    // }

    std::atomic<bool> got_result(false);
    std::string result_msg;
    uint16_t src_port = 40000 + (rand() % 10000);
    uint32_t seq = libnet_get_prand(LIBNET_PRu32);
    uint32_t src_ip, dst_ip;
    uint8_t flags = TH_FIN;

    std::thread sniffer([&]() {
        auto start = std::chrono::steady_clock::now();
        while (!got_result) {
            if (std::chrono::steady_clock::now() - start >= std::chrono::seconds(2)) {
                // 超时，主动退出
                break;
            }
            struct pcap_pkthdr* header;
            const u_char* pkt_data;
            // std::cout << "[DEBUG] 11Waiting for packets..." << std::endl;

            int res = pcap_next_ex(handle, &header, &pkt_data);

            // std::cout << "[DEBUG] pcap_next_ex returned: " << res << std::endl;

            if (res == 1) {
                const struct ip* ip_hdr = (struct ip*)(pkt_data + 14);
                const struct tcphdr* tcp_hdr = (const struct tcphdr*)(pkt_data + 14 + ip_hdr->ip_hl * 4);
                std::cout << "[DEBUG] Got TCP packet: sport=" << ntohs(tcp_hdr->th_sport)
                          << " dport=" << ntohs(tcp_hdr->th_dport)
                          << " flags=0x" << std::hex << (int)tcp_hdr->th_flags << std::dec << std::endl;
                if (ntohs(tcp_hdr->th_dport) == src_port && ntohs(tcp_hdr->th_sport) == port) {
                    if (tcp_hdr->th_flags & TH_RST) {
                        result_msg = "Port " + std::to_string(port) + " is CLOSED (RST received)";
                        got_result = true;
                        break;
                    }
                    // 收到其他响应不处理，继续等待
                }
            } else if (res == 0) {
                // 超时，无包到达
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                // std::cout << "[DEBUG] pcap_next_ex timeout, waiting for packets..." << std::endl;
            } else if (res == -1) {
                std::cerr << "[DEBUG] pcap_next_ex error: " << pcap_geterr(handle) << std::endl;
                break;
            }
        }
        got_result = true; // 保证主线程不会卡住
    });

    char errbuf[LIBNET_ERRBUF_SIZE] = {0};
    libnet_t *l = libnet_init(LIBNET_RAW4, iface.c_str(), errbuf);
    if (!l) {
        std::cerr << "libnet_init() failed: " << errbuf << std::endl;
        got_result = true;
        sniffer.join();
        pcap_close(handle);
        return;
    }
    src_ip = libnet_get_ipaddr4(l);
    dst_ip = libnet_name2addr4(l, const_cast<char*>(ip.c_str()), LIBNET_RESOLVE);
    libnet_build_tcp(
        src_port, port, seq, 0, flags, 32767, 0, 0, LIBNET_TCP_H, nullptr, 0, l, 0
    );
    libnet_build_ipv4(
        LIBNET_IPV4_H + LIBNET_TCP_H, 0, libnet_get_prand(LIBNET_PRu16), 0, 64, IPPROTO_TCP, 0,
        src_ip, dst_ip, nullptr, 0, l, 0
    );
    if (libnet_write(l) < 0) {
        std::cerr << "libnet_write() failed: " << libnet_geterror(l) << std::endl;
        got_result = true;
        sniffer.join();
        pcap_close(handle);
        libnet_destroy(l);
        return;
    }

    // std::cout << "[DEBUG] SYN packet sent to port " << port << " from source port " << src_port << std::endl;
    
    sniffer.join();

    // std::cout << "[DEBUG] Sniffer thread finished" << std::endl;

    if (!result_msg.empty()) {
        std::cout << result_msg << std::endl;
    } else {
        // FIN扫描无响应视为 open|filtered
        std::cout << "Port " << port << " is open|filtered (no response)" << std::endl;
    }
    pcap_close(handle);
    libnet_destroy(l);
}

void TCPSynScan(const std::string& ip, int option) {
    std::vector<int> ports;
    if (option == 0) {
        for (int p = 1; p <= 1024; ++p) ports.push_back(p);
    } else if (option == 1) {
        int port;
        std::cout << "Port #: ";
        std::cin >> port;
        ports.push_back(port);
    } else if (option == 2) {
        ports = commonPorts; // 使用预定义的常见端口
    } else {
        std::cout << "Invalid option.\n";
        return;
    }
    std::cout << "[SYN] 扫描 " << ip << " ...\n";
    for (int port : ports) {
        tcp_syn_scan(ip, port);
    }
}

void TCPFinScan(const std::string& ip, int option) {
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
    std::cout << "[FIN] 扫描 " << ip << " ...\n";
    for (int port : ports) {
        tcp_fin_scan(ip, port);
    }
}


// UDP端口扫描实现
// 
// 调试用：打印ICMP消息详情
void print_icmp_debug(uint8_t type, uint8_t code, uint16_t orig_port) {
    std::cout << "【ICMP调试】类型: " << (int)type 
              << ", 代码: " << (int)code 
              << ", 原始端口: " << orig_port << std::endl;
}

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

    // 增加超时时间到3秒（避免网络延迟导致漏检）
    const int SCAN_TIMEOUT = 3;

    for (int port : ports) {
        std::atomic<bool> port_closed(false);
        std::atomic<bool> thread_running(true);
        std::mutex mtx;
        std::condition_variable cv;

        // 调试标记：是否捕获到任何ICMP包
        std::atomic<bool> captured_icmp(false);

        std::string iface = get_interface_for_target(ip);
        std::cout << "\n=== 扫描端口 " << port << " ===" << std::endl;
        std::cout << "抓包网卡: " << iface << ", 目标IP: " << ip << std::endl;

        // 打开pcap句柄（超时设为100ms，避免阻塞过久）
        char pcap_errbuf[PCAP_ERRBUF_SIZE] = {0};
        pcap_t* handle = pcap_open_live(iface.c_str(), 65536, 1, 100, pcap_errbuf);
        if (!handle) {
            std::cerr << "❌ pcap_open_live失败: " << pcap_errbuf << std::endl;
            continue;
        }

        // 设置非阻塞模式
        if (pcap_setnonblock(handle, 1, pcap_errbuf) == -1) {
            std::cerr << "❌ pcap_setnonblock失败: " << pcap_errbuf << std::endl;
            pcap_close(handle);
            continue;
        }

        // 过滤规则：捕获目标IP的ICMP类型3消息（包含端口不可达）
        std::string filter_exp = "icmp[0] == 3 and src host " + ip;
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, filter_exp.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
            std::cerr << "❌ pcap_compile失败: " << pcap_geterr(handle) << std::endl;
            pcap_close(handle);
            continue;
        }
        if (pcap_setfilter(handle, &fp) == -1) {
            std::cerr << "❌ pcap_setfilter失败: " << pcap_geterr(handle) << std::endl;
            pcap_freecode(&fp);
            pcap_close(handle);
            continue;
        }
        pcap_freecode(&fp);
        std::cout << "✅ 过滤规则应用成功: " << filter_exp << std::endl;

        // 创建UDP套接字
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
            std::cerr << "❌ 创建UDP套接字失败: " << strerror(errno) << std::endl;
            pcap_close(handle);
            continue;
        }

        // 配置目标地址
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

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
                std::cout << "\n=== 捕获到第" << pkt_count << "个数据包 ===" << std::endl;

                // 1. 解析链路层，定位IP头部
                int linktype = pcap_datalink(handle);
                const u_char* ip_pkt = nullptr;
                switch (linktype) {
                    case DLT_EN10MB:    ip_pkt = pkt_data + 14; break;  // 以太网
                    case DLT_LINUX_SLL: ip_pkt = pkt_data + 16; break;  // Linux虚拟链路
                    case DLT_NULL:      ip_pkt = pkt_data + 4; break;   // _loopback
                    case DLT_RAW:       ip_pkt = pkt_data; break;       // 原始IP包
                    default:
                        std::cout << "❌ 不支持的链路类型: " << linktype << std::endl;
                        continue;
                }

                // 校验IP头部是否完整
                if (ip_pkt + sizeof(struct iphdr) > pkt_data + header->caplen) {
                    std::cout << "❌ IP包长度不足（至少需要" << sizeof(struct iphdr) << "字节）" << std::endl;
                    continue;
                }

                // 2. 解析IP头部
                const struct iphdr* ip_hdr = (const struct iphdr*)ip_pkt;
                std::cout << "IP协议: " << (ip_hdr->protocol == IPPROTO_ICMP ? "ICMP" : "未知") << std::endl;
                if (ip_hdr->protocol != IPPROTO_ICMP) {
                    std::cout << "❌ 非ICMP包，跳过" << std::endl;
                    continue;
                }

                // 3. 验证IP源地址
                struct in_addr src_ip;
                src_ip.s_addr = ip_hdr->saddr;
                std::string src_ip_str = inet_ntoa(src_ip);
                std::cout << "IP源地址: " << src_ip_str << (src_ip_str == ip ? "（匹配目标）" : "（不匹配）") << std::endl;
                if (src_ip_str != ip) continue;

                // 4. 解析ICMP头部
                int ip_hdr_len = ip_hdr->ihl * 4;
                const u_char* icmp_pkt = ip_pkt + ip_hdr_len;
                if (icmp_pkt + 2 > pkt_data + header->caplen) {  // 至少需要2字节（类型+代码）
                    std::cout << "❌ ICMP头部不完整（至少需要2字节）" << std::endl;
                    continue;
                }

                uint8_t icmp_type = icmp_pkt[0];
                uint8_t icmp_code = icmp_pkt[1];
                captured_icmp = true;  // 标记捕获到ICMP包

                // 5. 校验ICMP类型和代码（必须是类型3，代码3才是端口不可达）
                if (icmp_type != 3 || icmp_code != 3) {
                    print_icmp_debug(icmp_type, icmp_code, 0);
                    std::cout << "❌ 非端口不可达（类型3+代码3），跳过" << std::endl;
                    continue;
                }

                // 6. 解析ICMP中包含的原始UDP包（错误数据区）
                const u_char* orig_ip_pkt = icmp_pkt + 8;  // 跳过ICMP错误头部（8字节）
                if (orig_ip_pkt + sizeof(struct iphdr) > pkt_data + header->caplen) {
                    std::cout << "❌ 原始IP包长度不足" << std::endl;
                    continue;
                }

                const struct iphdr* orig_ip_hdr = (const struct iphdr*)orig_ip_pkt;
                if (orig_ip_hdr->protocol != IPPROTO_UDP) {
                    std::cout << "❌ 原始包非UDP协议，跳过" << std::endl;
                    continue;
                }

                // 7. 解析原始UDP头部，提取目标端口
                int orig_ip_len = orig_ip_hdr->ihl * 4;
                const u_char* orig_udp_pkt = orig_ip_pkt + orig_ip_len;
                if (orig_udp_pkt + sizeof(struct udphdr) > pkt_data + header->caplen) {
                    std::cout << "❌ 原始UDP包长度不足" << std::endl;
                    continue;
                }

                const struct udphdr* orig_udp_hdr = (const struct udphdr*)orig_udp_pkt;
                uint16_t orig_dst_port = ntohs(orig_udp_hdr->dest);
                print_icmp_debug(icmp_type, icmp_code, orig_dst_port);

                // 8. 验证端口是否匹配当前扫描端口
                if (orig_dst_port == port) {
                    std::cout << "✅ 匹配当前端口！判定为CLOSED" << std::endl;
                    port_closed = true;
                    break;  // 找到匹配的包，退出抓包
                } else {
                    std::cout << "❌ 端口不匹配（当前扫描" << port << "，包中是" << orig_dst_port << "）" << std::endl;
                }
            }

            std::cout << "抓包线程结束（总捕获" << pkt_count << "个包，" << (captured_icmp ? "有ICMP包" : "无ICMP包") << "）" << std::endl;
            thread_running = false;
            cv.notify_one();
        });

        // 发送UDP探测包（使用非空载荷，提高被响应概率）
        const char* payload = "NIS3302_UDP_SCAN";
        int send_len = sendto(sock, payload, strlen(payload), 0, (struct sockaddr*)&addr, sizeof(addr));
        if (send_len < 0) {
            std::cerr << "❌ 发送UDP包失败: " << strerror(errno) << std::endl;
        } else {
            std::cout << "✅ 已发送UDP探测包（长度: " << send_len << "字节）" << std::endl;
        }

        // 等待UDP响应
        char recvbuf[1024];
        socklen_t addrlen = sizeof(addr);
        int ret = recvfrom(sock, recvbuf, sizeof(recvbuf), 0, (struct sockaddr*)&addr, &addrlen);
        if (ret > 0) {
            std::cout << "✅ 收到UDP响应（长度: " << ret << "字节）" << std::endl;
        } else {
            std::cout << "⚠️ 未收到UDP响应（错误: " << strerror(errno) << "）" << std::endl;
        }

        // 等待抓包线程结束
        {
            std::unique_lock<std::mutex> lock(mtx);
            cv.wait_for(lock, std::chrono::seconds(SCAN_TIMEOUT), [&]{ return !thread_running; });
        }
        thread_running = false;
        sniffer.join();

        // 最终判定
        std::cout << "\n=== 端口" << port << "扫描结果 ===" << std::endl;
        if (port_closed) {
            std::cout << "✅ Port " << port << " is CLOSED (ICMP端口不可达)" << std::endl;
        } else if (ret > 0) {
            std::cout << "✅ Port " << port << " is OPEN (收到UDP响应)" << std::endl;
        } else {
            // 额外提示：是否捕获到ICMP包，帮助判断环境问题
            if (!captured_icmp) {
                std::cout << "⚠️ Port " << port << " is OPEN|FILTERED（未捕获到任何ICMP包，可能被防火墙拦截）" << std::endl;
            } else {
                std::cout << "⚠️ Port " << port << " is OPEN|FILTERED（未匹配到端口不可达消息）" << std::endl;
            }
        }

        // 清理资源
        pcap_close(handle);
        close(sock);
    }
}
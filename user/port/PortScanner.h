/**
 * PortScanner.h
 * 端口扫描功能的头文件
 * 提供各种端口扫描方法的声明
 */
#ifndef PORTSCANNER_H
#define PORTSCANNER_H

#include <string>
#include <vector>

/**
 * 测试指定IP地址和端口的连接状态
 * @param ip 目标IP地址
 * @param port 目标端口号
 * @return 如果端口开放则返回true，否则返回false
 */
bool TestPortConnection(std::string ip, int port);

/**
 * 获取本地主机名或IP地址
 * @return 本地主机名或IP地址
 */
std::string GetHost();

/**
 * 显示端口扫描选项菜单
 */
void DisplayOptions();

/**
 * 获取用户选择的选项
 * @return 用户选择的选项值
 */
int GetOption();

/**
 * 线程任务函数，用于测试单个端口
 * @param bufferArg 存储开放端口的缓冲区
 * @param hostNameArg 目标主机名或IP
 * @param port 要测试的端口号
 */
void ThreadTask(std::vector<int>* bufferArg, std::string hostNameArg, int port);

/**
 * 扫描目标主机的所有端口（1-65535）
 * @param hostNameArg 目标主机名或IP
 */
void ScanAllPorts(std::string hostNameArg);

/**
 * 扫描目标主机的指定端口
 * @param hostNameArg 目标主机名或IP
 * @param port 要扫描的端口号
 */
void ScanSpecificPort(std::string hostNameArg, int port);

/**
 * 扫描目标主机的常见端口
 * @param hostNameArg 目标主机名或IP
 */
void ScanCommonPorts(std::string hostNameArg);

/**
 * 使用TCP SYN方法进行端口扫描
 * @param ip 目标IP地址
 * @param option 扫描选项：0-所有端口，1-指定端口，2-常见端口
 */
void TCPSynScan(const std::string& ip, int option);

/**
 * 使用TCP FIN方法进行端口扫描
 * @param ip 目标IP地址
 * @param option 扫描选项：0-所有端口，1-指定端口，2-常见端口
 */
void TCPFinScan(const std::string& ip, int option);

/**
 * 使用UDP方法进行端口扫描
 * @param ip 目标IP地址
 * @param option 扫描选项：0-所有端口，1-指定端口，2-常见端口
 */
void UDPScan(const std::string& ip, int option);

#endif
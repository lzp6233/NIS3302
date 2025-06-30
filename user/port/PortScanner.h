#ifndef PORTSCANNER_H
#define PORTSCANNER_H

#include <string>
#include <vector>

// 测试端口是否开放
bool TestPortConnection(std::string ip, int port);

// 获取主机名或IP
std::string GetHost();

// 显示选项菜单
void DisplayOptions();

// 获取用户选择的选项
int GetOption();

// 线程任务：测试单个端口
void ThreadTask(std::vector<int>* bufferArg, std::string hostNameArg, int port);

// 扫描所有端口
void ScanAllPorts(std::string hostNameArg);

// 扫描指定端口
void ScanSpecificPort(std::string hostNameArg);

// 扫描常见端口
void ScanCommonPorts(std::string hostNameArg);

#endif
/*
 * Copyright (c) 2023 Jan Wilmans, MIT License
 */

/**
 * network.h
 * 网络相关工具函数的头文件
 * 提供DNS查询、反向DNS查询和网卡信息获取功能
 */

#include <string>
#include <vector>

/**
 * 执行DNS查询，将主机名解析为IP地址
 * @param hostname 要解析的主机名
 * @return 解析得到的IP地址字符串
 */
std::string dns_lookup(const std::string & hostname);

/**
 * 执行反向DNS查询，将IP地址解析为主机名
 * @param ipaddress 要解析的IP地址
 * @return 解析得到的主机名字符串
 */
std::string reverse_dns_lookup(const std::string & ipaddress);

/**
 * 获取系统中所有物理网卡的名称列表
 * @return 包含网卡名称的字符串向量
 */
std::vector<std::string> get_physical_networkcard_names();
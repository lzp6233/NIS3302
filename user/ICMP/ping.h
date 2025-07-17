/**
 * ping.h
 * ICMP协议ping功能的头文件定义
 * 提供基于ICMP协议的ping功能
 */
#ifndef _ping_h
#define _ping_h

#pragma once
#include <string>
#include <chrono>
#include <optional>

/**
 * 定义毫秒精度的浮点数时间类型
 */
using double_milliseconds = std::chrono::duration<double, std::milli>;

namespace icmp_ns {

/**
 * ICMP ping函数
 * 向目标地址发送ICMP Echo请求并等待响应
 * 
 * @param address 目标IP地址或域名
 * @param timeout 等待响应的最长时间
 * @return 如果成功收到响应，返回响应所用时间；如果超时，返回空
 */
std::optional<double_milliseconds> ping(const std::string& address, std::chrono::milliseconds timeout);

}

#endif
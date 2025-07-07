#ifndef _ping_h
#define _ping_h

#pragma once
#include <string>
#include <chrono>
#include <optional>

using double_milliseconds = std::chrono::duration<double, std::milli>;

namespace icmp_ns {

// ICMP ping，返回耗时（毫秒），超时则返回空
std::optional<double_milliseconds> ping(const std::string& address, std::chrono::milliseconds timeout);

}

#endif
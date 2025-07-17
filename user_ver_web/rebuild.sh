#!/bin/bash
# rebuild.sh - 项目重建脚本
# 用于清理旧的构建文件并重新编译网页版端口扫描工具

# 删除旧的构建目录
rm -rf build
# 创建新的构建目录
mkdir build
# 进入构建目录
cd build
# 使用CMake生成构建系统
cmake ..
# 编译项目
make
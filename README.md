# NIS3302 信息安全科技创新

本项目为信息安全科技创新课程的小组作业，旨在实现一个基础的网络端口扫描系统，支持ICMP、TCP和UDP协议的端口扫描。项目使用C++编写，采用面向对象的设计模式，具有良好的可扩展性和可维护性。

## 小组成员

- 刘梓芃 523031910639 liuzipeng@sjtu.edu.cn
- 聂鸣涛 523031910728 niemingtao@sjtu.edu.cn
- 李卓恒 523031910556 lzhsj32206@sjtu.edu.cn
- 张煜哲 523031910110 zhangyuzhe@sjtu.edu.cn

## 项目结构

```
NIS3302/
├── README.md                # 项目说明文档
├── .gitignore               # Git忽略文件配置
├── reference/               # 参考资料与实验代码
│   ├── explain_icmp_ping/       # ICMP ping相关参考实现
│   │   ├── build-c.sh
│   │   ├── build-cpp.sh
│   │   ├── LICENSE
│   │   ├── README.md
│   │   └── src/
│   ├── port-scanner-cpp-main/   # 其他端口扫描器参考项目
│   │   └── port-scanner-cpp-main/
│   └── PortScanner-master/      # 其他端口扫描器参考项目
│       └── PortScanner-master/
├── report/                  # 各类报告模板
│   ├── 总体设计报告模板.docx
│   ├── 结题报告模板.doc
│   └── 选题表模板.doc
├── user/                    # 主要代码目录
│   ├── CMakeLists.txt       # CMake构建脚本
│   ├── main.cpp             # 程序入口
│   ├── build/               # 构建输出目录
│   ├── ICMP/                # ICMP协议相关实现
│   │   ├── network.cpp
│   │   ├── network.h
│   │   ├── ping.cpp
│   │   └── ping.h
│   └── port/                # 端口扫描相关实现（建议将端口扫描相关源码放在此目录）
│       └── ...              # 端口扫描相关源文件

```

> 说明：  
> - 主要开发目录为 `user/`，其中 ICMP/ 负责 ICMP 协议实现，port/ 负责端口扫描实现，main.cpp 为主程序入口。  
> - 参考项目和资料位于 reference/ 目录下，包括 explain_icmp_ping、port-scanner-cpp-main、PortScanner-master。  
> - 报告模板和文档位于 report/。
## 安装说明
### 安装 libnet 开发库
```bash
sudo apt update
sudo apt install libnet1-dev
```

### 安装 libpcap 开发库
```bash
sudo apt update
sudo apt install libpcap-dev
```
## 使用说明

1. **编译项目**
   ```bash
   cd user
   mkdir build
   cd build
   cmake ..
   make
   ```
   编译完成后会在 `build/` 目录下生成可执行文件 `portScan`。
    
2. **运行程序**
   ```bash
   ./portScan
   ```
   按照提示输入目标IP地址和扫描选项，即可进行ICMP主机存活检测和TCP端口扫描。

3. **主要功能**
   - ICMP扫描（类似ping）：检测主机是否存活。
   - TCP端口扫描：支持全端口扫描、常用端口扫描、指定端口扫描。
   - 结果以命令行形式输出。

4. **目录结构说明**
   - `user/ICMP/`：ICMP协议相关实现（如ping功能）。
   - `user/port/`：端口扫描相关实现。
   - `user/main.cpp`：主程序入口。
   - `reference/`：参考项目和资料。
   - `report/`：各类报告模板和文档。

5. **依赖库**
   - `libnet`：用于构造和发送原始数据包。
   - `libpcap`：用于捕获网络数据包。
   - `fmt`：格式化输出库。
   - `docopt`：命令行参数解析库。

6. **常见问题**
   - 需使用root权限运行以获取原始套接字权限。
   - 若遇到依赖库缺失，请先按照上方“安装说明”安装相关开发库。

7. **联系方式**
   - 如有问题或建议，请联系项目成员或提交issue。

# NIS3302 信息安全科技创新 - 网络端口扫描系统

本项目为信息安全科技创新课程的小组作业，旨在实现一个多功能的网络端口扫描系统，支持ICMP、多种TCP和UDP协议的端口扫描。项目分为命令行版本和Web版本，具备以下特点：

- **多协议支持**：实现了ICMP、TCP Connect、TCP SYN、TCP FIN、UDP等多种扫描协议
- **高性能设计**：基于多线程架构，高效处理大规模端口扫描任务
- **友好的界面**：Web版本提供直观的图形界面，实时展示扫描结果和统计图表
- **科学的分析**：对不同协议的扫描结果进行专业分析和展示，尤其是UDP扫描结果
- **全面的功能**：支持端口服务识别、扫描历史记录、结果导出等实用功能

项目使用C++编写，采用面向对象的设计模式，具有良好的可扩展性和可维护性。Web版本使用了现代前端技术，提供了更加直观和易用的操作体验。

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
├── report/                  # 各类报告模板
│   ├── 总体设计报告模板.docx
│   ├── 结题报告模板.doc
│   └── 选题表模板.doc
├── user/                    # 命令行版本代码目录
│   ├── CMakeLists.txt       # CMake构建脚本
│   ├── main.cpp             # 程序入口
│   ├── build/               # 构建输出目录
│   ├── ICMP/                # ICMP协议相关实现
│   │   ├── network.cpp      # 网络底层实现
│   │   ├── network.h
│   │   ├── ping.cpp         # ICMP ping功能实现
│   │   └── ping.h
│   └── port/                # 端口扫描相关实现
│       ├── PortScanner.cpp  # 端口扫描器核心实现
│       └── PortScanner.h
└── user_ver_web/            # Web版本代码目录
    ├── CMakeLists.txt       # Web版本CMake构建脚本
    ├── main.cpp             # Web服务器入口及接口实现
    ├── port_scanner.html    # 前端界面（HTML, CSS, JavaScript）
    ├── rebuild.sh           # 快速重建脚本
    ├── build/               # Web版本构建输出目录
    │   └── portScan         # Web版本可执行文件
    ├── ICMP/                # ICMP协议实现（同命令行版）
    │   ├── network.cpp
    │   ├── network.h
    │   ├── ping.cpp
    │   └── ping.h
    └── port/                # 端口扫描实现（Web适配版）
        ├── PortScanner.cpp  # Web适配的端口扫描器实现
        └── PortScanner.h
```

> 说明：  
> - `user/`目录包含命令行版本的端口扫描器代码
> - `user_ver_web/`目录包含Web版本的端口扫描器代码，使用了C++后端和HTML/JavaScript前端
> - 两个版本共享相似的核心扫描逻辑，但Web版本增加了HTTP服务器和更友好的图形界面
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
## 使用说明（命令行）

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

## 使用说明（网页）

### 编译项目
   ```bash
   cd user_ver_web
   mkdir build
   cd build
   cmake ..
   make
   ```

### 运行

#### 运行后端（终端1）
```bash
cd /home/zipeng_liu/NIS3302/user_ver_web/build
sudo ./portScan   # 需要sudo权限以使用原始套接字
```
后端启动后会监听8080端口，并提供REST API服务。

#### 运行前端（终端2）
```bash
cd /home/zipeng_liu/NIS3302/user_ver_web
python3 -m http.server 8000
```

#### 浏览器访问
打开浏览器访问 `http://localhost:8000/port_scanner.html`

### Web版功能

#### 支持的扫描类型
1. **ICMP扫描** - 检测主机是否存活（类似ping）
2. **TCP Connect扫描** - 标准的TCP完全连接扫描
3. **TCP SYN扫描** - 半开放式扫描，只发送SYN包
4. **TCP FIN扫描** - 发送FIN包的隐蔽扫描
5. **UDP扫描** - UDP端口扫描，检测UDP服务

#### 端口范围选择
- **常用端口** - 扫描53个最常用的端口
- **所有端口** - 扫描全部65535个端口（较耗时）
- **自定义范围** - 手动指定要扫描的端口

#### 高级选项
- **线程数** - 控制并发扫描线程数
- **超时时间** - 设置连接超时时间(毫秒)
- **解析主机名** - 尝试解析扫描结果的主机名
- **检测服务版本** - 尝试识别端口上运行的服务版本

#### 结果展示
- **扫描状态** - 实时显示扫描进度
- **图表展示** - 用饼图显示开放/关闭/过滤端口分布
- **端口表格** - 详细显示各端口状态和服务信息
- **扫描历史** - 保存历史扫描记录
- **结果导出** - 支持导出扫描结果

#### UDP扫描特性
UDP扫描结果包含三种状态：
- **开放** - 收到UDP响应，端口确实开放
- **开放|过滤** - 未收到响应，可能开放或被防火墙过滤
- **关闭** - 收到ICMP端口不可达错误，端口确实关闭

> 注意：UDP扫描需要root权限才能捕获ICMP错误消息，否则大多数端口会被误报为"开放|过滤"状态。

## 依赖库说明

### 后端依赖
- **libnet**：用于构造和发送各类网络数据包
  ```bash
  sudo apt install libnet1-dev
  ```

- **libpcap**：用于捕获和分析网络数据包
  ```bash
  sudo apt install libpcap-dev
  ```

- **cpp-httplib**：轻量级C++ HTTP/HTTPS服务器和客户端库（已包含在代码中）

- **nlohmann/json**：现代C++ JSON处理库（已包含在代码中）

- **fmt**：现代C++格式化库
  ```bash
  sudo apt install libfmt-dev # 或通过CMake自动下载
  ```

### 前端依赖
- **Tailwind CSS**：通过CDN引入
- **Chart.js**：用于绘制扫描结果图表
- **Font Awesome**：图标库

# VulnMiner - 高级全自动化漏洞扫描与赏金获取系统

🚀 **版本**: 1.0.0 | **模式**: 个人使用 | **平台**: 跨平台

VulnMiner 是一个为安全研究人员个人使用而设计的高级全自动化漏洞扫描和漏洞赏金系统。通过智能工具编排和自动化报告提供全面的漏洞发现能力。

## 🎯 核心特性

### 🔄 双重操作模式
- **🔍 SCAN 模式**: 手动目标输入，智能漏洞扫描
- **🤖 AUTO 模式**: 从漏洞赏金平台自动获取目标

### ⚡ 先进扫描能力
- **5阶段扫描管道**: 发现 → 枚举 → 漏洞扫描 → 验证 → 报告
- **20+安全工具集成**: nmap, nuclei, subfinder, httpx, gobuster, sqlmap, amass 等
- **智能工具编排**: 基于目标特征的自动工具选择
- **实时进度跟踪**: 基于WebSocket的进度更新和ML时间估算

### 🌍 跨平台兼容性
- **Windows**: 完整的UAC处理和Windows优化
- **Linux**: 原生Linux支持和sudo管理  
- **Google Colab**: 云端扫描和Colab配置
- **Docker**: 容器化部署，隔离扫描环境

## 📋 系统要求

### 最低要求
- **Python**: 3.8 或更高版本
- **内存**: 4GB RAM (推荐 8GB)
- **存储**: 2GB 可用空间用于工具和数据库
- **网络**: 互联网连接用于工具更新和API访问

### 必需安全工具
以下工具为必需，系统将自动检测：
- **nmap** (>= 7.80) - 网络发现和端口扫描（唯一端口扫描工具）
- **nuclei** (>= 2.9.0) - 基于模板引擎的漏洞扫描器
- **subfinder** (>= 2.6.0) - 子域名发现
- **httpx** (>= 1.3.0) - HTTP工具包探测
- **gobuster** (>= 3.5) - 目录/DNS/VHost枚举

## 🚀 快速开始

### 1. 安装Python依赖
```bash
pip install -r requirements.txt
```

### 2. 安装安全工具
```bash
# 自动化安装（推荐）
python ../install_tools.py

# 或手动安装Go工具
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/OJ/gobuster/v3@latest
```

### 3. 验证安装
```bash
python start.py --check-deps
python start.py --health-check
```

## 💻 使用方法

### Windows用户
```batch
REM 基础Web应用扫描
start.bat scan --target https://example.com --pipeline webapp

REM 全面网络扫描  
start.bat scan --target 192.168.1.0/24 --pipeline comprehensive

REM HackerOne自动化扫描
start.bat auto --platform hackerone --max-targets 5
```

### Linux/macOS用户
```bash
# 基础Web应用扫描
python start.py scan --target https://example.com --pipeline webapp

# 多目标扫描
python start.py scan --target-list targets.txt --pipeline comprehensive --submit

# 漏洞赏金平台自动扫描
python start.py auto --platform bugcrowd --continuous
```

## ⚙️ 扫描管道

### 🏃 快速管道 (~2-5 分钟)
- **目的**: 快速侦察和高优先级漏洞检测
- **工具**: nmap (快速扫描), nuclei (关键模板)
- **使用场景**: 快速评估, CI/CD集成

### 🔍 全面管道 (~15-30 分钟)
- **目的**: 彻底的漏洞评估
- **工具**: 完整nmap扫描, 完整nuclei模板, 子域名枚举
- **使用场景**: 完整安全审计, 渗透测试

### 🌐 Web应用管道 (~10-20 分钟)
- **目的**: Web应用程序特定测试
- **工具**: httpx探测, 目录枚举, Web漏洞扫描
- **使用场景**: Web应用安全评估

### 🔗 网络管道 (~20-45 分钟)
- **目的**: 网络基础设施评估
- **工具**: 全面端口扫描, 服务枚举, 网络漏洞
- **使用场景**: 内网评估, 基础设施测试

## 📊 报告格式

- **📄 HTML报告**: 带图表的交互式仪表板
- **📋 PDF报告**: 面向利益相关者的执行摘要  
- **💾 JSON报告**: 机器可读格式，便于集成
- **🔧 SARIF报告**: 静态分析结果交换格式

## 🔒 安全注意事项

### ⚠️ 授权和安全
- **默认仅白名单扫描**
- **速率限制** 防止服务中断
- **所有扫描活动审计日志**
- **端口扫描仅使用nmap**

### 📤 负责任披露
- **自动平台提交** 和适当格式化
- **漏洞验证** 和误报过滤
- **奖励跟踪** 和提交状态

## 🛠️ 配置

### 环境变量
```bash
# HackerOne
set HACKERONE_USERNAME=your_username
set HACKERONE_API_TOKEN=your_api_token

# Bugcrowd
set BUGCROWD_EMAIL=your_email
set BUGCROWD_PASSWORD=your_password

# 系统配置
set VULN_MINER_DEBUG=false
set VULN_MINER_MAX_CONCURRENT=5
```

### 配置文件
主配置文件: `../config/default.yml`

## 🆘 故障排除

### 常见问题

**❓ ImportError: cannot import name 'VulnMinerCLI'**
- ✅ 解决: 使用vuln_scanner目录中的start.py

**❓ 工具未找到错误**  
- ✅ 解决: 运行 `python start.py --check-deps` 检查工具安装

**❓ 配置错误**
- ✅ 解决: 运行 `python start.py --validate-config` 验证配置

### 获取帮助
```bash
# 查看所有选项
python start.py --help

# 查看特定模式帮助
python start.py scan --help
python start.py auto --help

# 系统诊断
python start.py --health-check
python start.py --check-deps
```

## ⚠️ 免责声明

VulnMiner 仅用于授权安全测试和漏洞赏金狩猎。用户有责任确保在扫描任何目标之前获得适当的授权。作者对软件的任何误用或造成的损害概不负责。

---

**🚀 现在可以使用VulnMiner开始您的漏洞研究之旅！**

*"自动化道德黑客的艺术"*
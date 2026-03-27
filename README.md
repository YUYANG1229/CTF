# CTF Web Toolkit

CTF Web 安全竞赛工具集，支持 macOS / Windows / Linux，无需安装 Python，单文件可执行。

## 下载

前往 [Releases](../../releases) 页面下载对应平台的可执行文件：

| 平台 | 文件 |
|------|------|
| macOS Apple Silicon (M1/M2/M3) | `ctf-toolkit-macos-arm64` |
| macOS Intel | `ctf-toolkit-macos-x64` |
| Windows 10/11 | `ctf-toolkit-windows-x64.exe` |
| Linux | `ctf-toolkit-linux-x64` |

## 快速开始

```bash
# macOS / Linux
chmod +x ctf-toolkit-macos-arm64
./ctf-toolkit-macos-arm64 --help

# Windows
ctf-toolkit-windows-x64.exe --help
```

## 功能模块

### 攻击模块

| 命令 | 说明 |
|------|------|
| `scan` | 综合扫描（XSS / SQLi / SSTI / LFI / SSRF / CMDI）|
| `sqli` | SQL 注入检测与利用（布尔盲注 / 时间盲注 / 报错注入）|
| `xss` | XSS 漏洞扫描（反射型 / 存储型 / DOM型）|
| `ssrf` | SSRF 探测（内网扫描 / 端口探测 / 云元数据）|
| `ssti` | SSTI 模板注入（Jinja2 / Twig / Velocity / Smarty / Mako）|
| `lfi` | 本地文件包含（路径穿越 / 伪协议 / 日志注入）|
| `cmdi` | 命令注入检测（基于时间 / DNS 回显）|
| `xxe` | XXE 注入（文件读取 / OOB / SSRF / SVG / XInclude）|
| `nosqli` | NoSQL 注入（MongoDB 认证绕过 / 盲注 / Redis Gopher）|
| `jwt` | JWT 攻击（none算法 / 弱密钥爆破 / 公钥混淆）|
| `redirect` | 开放重定向扫描与绕过 |
| `upload` | 文件上传绕过（扩展名 / MIME / 双后缀 / 竞争条件）|
| `webshell` | Webshell 生成（PHP / JSP / ASPX / Python / Node）|
| `immortal` | 不死马生成（PHP 进程驻留）|
| `shell` | Webshell 连接客户端（菜刀协议 / 冰蝎 AES）|

### 防御模块

| 命令 | 说明 |
|------|------|
| `audit` | 综合安全审计（安全头 / WAF识别 / 信息泄露）|
| `cors` | CORS 错误配置检测 |
| `encode` | 编解码工具（Base64 / URL / Hex / MD5 / SHA / ROT13）|

## 使用示例

```bash
# SQL 注入
./ctf-toolkit sqli http://target.com/index.php --param id

# XSS 扫描
./ctf-toolkit xss http://target.com/search --param q

# SSRF 探测内网
./ctf-toolkit ssrf http://target.com/fetch --param url --action probe

# SSTI 检测并利用
./ctf-toolkit ssti http://target.com/page --param name --action exploit --engine jinja2

# XXE 文件读取
./ctf-toolkit xxe http://target.com/upload --action read --file /etc/passwd

# JWT 攻击
./ctf-toolkit jwt --token "eyJ..." --action crack --wordlist rockyou.txt

# 生成 PHP Webshell
./ctf-toolkit webshell --lang php --action generate --password cmd

# 编码/解码
./ctf-toolkit encode "hello world" --action all

# 安全审计
./ctf-toolkit audit http://target.com
```

## 本地构建

### macOS

```bash
# 安装依赖并构建
make

# 或手动
bash build_mac.sh
```

### Windows

```cmd
build_windows.bat
```

### 自动发布（GitHub Actions）

推送 tag 自动构建全平台：

```bash
git tag v1.0.0
git push origin v1.0.0
```

## 依赖

- Python 3.9+
- requests
- pycryptodome
- colorama

> 使用预编译二进制无需安装任何依赖

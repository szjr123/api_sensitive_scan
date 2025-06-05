# API扫描工具 (API Scanner)

API扫描工具，用于发现API端点、检测敏感信息泄露。

## 功能特点

- **API路径扫描**：使用自定义字典扫描API端点
- **敏感信息检测**：自动识别API响应中的敏感信息（如API密钥、JWT令牌、个人信息等）
- **智能状态码处理**：根据不同HTTP状态码采取不同处理策略
- **并发扫描**：支持高并发请求，提高扫描效率
- **详细报告**：生成JSON格式的详细扫描报告
- **自定义配置**：支持代理、认证令牌、自定义UA等配置

## 状态码处理逻辑

工具针对不同的HTTP状态码采用不同的处理策略：

- **200 OK**：只保存包含敏感信息泄露的URL和相关信息
- **403 Forbidden**：只保留URL，不进行其他处理
- **404 Not Found**：直接跳过，不保留任何结果
- **5xx 服务器错误**：跳过并记录错误请求计数
- **其他状态码**：按原有逻辑处理

## 安装

### 前置条件

- Rust 1.56.0 或更高版本
- Cargo 包管理器

### 安装步骤

1. 克隆仓库：

```bash
git clone https://github.com/yourusername/api-scanner.git
cd api-scanner
```

2. 编译项目：

```bash
cargo build --release
```

编译后的可执行文件将位于 `target/release/` 目录下。

## 使用方法

### 基本用法

```bash
./api-scanner --target https://api.example.com --dictionary ./config/api_dict.txt
```

### 完整参数

```bash
./api-scanner \
  --target https://api.example.com \
  --dictionary ./config/api_dict.txt \
  --output ./results/scan_report.json \
  --concurrency 20 \
  --timeout 10 \
  --user-agent-file ./config/user-agents.txt \
  --auth-token YOUR_AUTH_TOKEN \
  --proxy http://localhost:8080 \
  --include-paths ./config/include.txt \
  --exclude-paths ./config/exclude.txt
```

## 配置选项

| 参数 | 描述 | 默认值 |
|------|------|--------|
| `--target`, `-t` | 目标URL (必需) | - |
| `--dictionary`, `-d` | API路径字典文件 | ./config/api_dict.txt |
| `--output`, `-o` | 输出报告文件路径 | ./config/scan_report.json |
| `--concurrency`, `-c` | 并发请求数量 | 20 |
| `--timeout` | 请求超时时间(秒) | 10 |
| `--proxy` | 代理服务器URL | - |
| `--auth-token` | Bearer认证令牌 | - |
| `--user-agent-file` | User-Agent列表文件 | ./config/user-agents.txt |
| `--include-paths` | 要包含的额外路径文件 | - |
| `--exclude-paths` | 要排除的路径文件 | - |


## 输出报告

扫描完成后，工具会生成一个JSON格式的详细报告，包含以下信息：

- 基本扫描结果（成功的请求）
- 敏感信息发现
- 403状态码URL列表
- 5xx错误计数
- 扫描配置和统计信息

## 敏感信息检测

工具可以检测多种类型的敏感信息，包括但不限于：

- 电子邮件地址
- 手机号码
- API密钥
- JWT令牌
- 信用卡号
- 中国身份证号
- 私钥信息

## 开发

### 项目结构

```
src/
├── main.rs              # 程序入口
├── lib.rs
├── function/
│   ├── mod.rs           # 模块声明
│   ├── config.rs        # 配置处理
│   ├── scanner.rs       # 扫描核心逻辑
│   ├── vulnerability.rs # 敏感信息检测
│   ├── report.rs        # 结果结构定义
│   └── error.rs         # 错误处理
├── config/              # 配置文件目录
│   ├── api_dict.txt     # API路径字典
│   ├── user-agents.txt  # User-Agent列表
└──

### 扩展敏感信息检测

要添加新的敏感信息检测规则，修改 `vulnerability.rs` 中的 `create_patterns` 函数：

```rust
fn create_patterns() -> Vec<(String, Regex)> {
    vec![ 
        // 现有规则...
        
        // 添加新规则
        ("新敏感信息类型".to_string(), Regex::new(r"正则表达式模式").unwrap()),
    ]
}
```
### 请求头信息添加修改
自定义请求头，修改
```rust
async fn comprehensive_scan(
    client: Client,
    config: &Config,
    paths: Vec<String>,
) -> Result<ComprehensiveScanReport, ScanError> {
  //......
  let scan_result = ......
}
```

## 免责声明

本工具仅用于授权的安全测试和教育目的。未经明确许可，对任何系统进行扫描可能违反法律。使用者需承担所有责任。

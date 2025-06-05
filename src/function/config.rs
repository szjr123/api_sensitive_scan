// config.rs
use structopt::StructOpt;
use std::path::PathBuf;
use super::ScanError;

#[derive(Debug, StructOpt)]
pub struct Config {
    /// 目标 URL (例如: https://api.example.com)
    #[structopt(short, long)]
    pub target: String,

    /// 字典文件路径
    #[structopt(short, long, default_value = "./config/api_dict.txt")]
    pub dictionary: PathBuf,

    /// 输出报告文件路径
    #[structopt(short, long, default_value = "./config/scan_report.json")]
    pub output: PathBuf,

    /// 并发请求数量
    #[structopt(short, long, default_value = "20")]
    pub concurrency: usize,

    /// 请求超时时间 (秒)
    #[structopt(long, default_value = "10")]
    pub timeout: u64,

    /// 代理服务器 (例如: http://localhost:8080)
    #[structopt(long)]
    pub proxy: Option<String>,

    /// 认证令牌 (Bearer 令牌)
    #[structopt(long)]
    pub auth_token: Option<String>,

    /// User-Agent列表文件路径
    #[structopt(
        long,
        default_value = "./config/user-agents.txt",
        help = "User-Agent列表文件路径,每一行一个UA字符串"
    )]
    pub user_agent_file: PathBuf,

    /// 包含路径的文件 (每行一个路径)
    #[structopt(long)]
    pub include_paths: Option<PathBuf>,

    /// 排除路径的文件 (每行一个路径)
    #[structopt(long)]
    pub exclude_paths: Option<PathBuf>,
}

impl Config {
    pub fn validate(&self) -> Result<(), ScanError> {
        // 目标url格式验证
        if !self.target.starts_with("http://") && !self.target.starts_with("https://") {
            return Err(ScanError::InvalidConfig("请输入正确的URL".to_string()));
        }
        
        // 验证字典路径存在
        if !self.dictionary.exists() {
            return Err(ScanError::InvalidConfig("字典文件不存在。".to_string()));
        }
        
        // 验证并发合理性
        if self.concurrency == 0 || self.concurrency > 100 {
            return Err(ScanError::InvalidConfig("并发数区间为1~100。".to_string()));
        }
        
        // 验证令牌
        if let Some(token) = &self.auth_token {
            if token.trim().is_empty() {
                return Err(ScanError::InvalidConfig("认证令牌不能为空。".to_string()));
            }
            if token.contains(".") {
                let parse: Vec<&str> = token.split('.').collect();
                if parse.len() != 3 {
                    return Err(ScanError::InvalidConfig("JWT令牌格式无效。".to_string()));
                }
            }
        }
        
        // 验证代理
        if let Some(proxy) = &self.proxy {
            if !proxy.starts_with("http://") && !proxy.starts_with("https://") {
                return Err(ScanError::InvalidConfig("代理URL必须以http://或https://开头".to_string()));
            }
        }
        
        // 验证UA文件
        if !self.user_agent_file.exists() {
            return Err(ScanError::InvalidConfig("UA文件不存在。".to_string()));
        }
        if std::fs::metadata(&self.user_agent_file)?.len() == 0 {
            return Err(ScanError::InvalidConfig("UA文件不能为空.".to_string()));
        }
        
        Ok(())
    }
}
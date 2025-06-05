//错误处理板块
use thiserror::Error;
use std::io;

#[derive(Error, Debug)]
pub enum ScanError {
    #[error("配置错误: {0}")]
    InvalidConfig(String),
    
    #[error("网络错误: {0}")]
    NetworkError(String),   
    
    #[error("文件操作错误: {0}")]
    IOError(String),        
    
    #[error("解析错误: {0}")]
    ParseError(String),     
    
    #[error("报告生成错误: {0}")]
    ReportError(String),
    
    #[error("请求失败: {0}")]
    RequestFailed(String),
    
    #[error("HTTP客户端错误: {0}")]
    ClientError(String),
    
    #[error("序列化错误: {0}")]
    SerializationError(String),
}
 

impl From<io::Error> for ScanError {
    fn from(err: io::Error) -> Self {
        ScanError::IOError(err.to_string())
    }
}

impl From<reqwest::Error> for ScanError {
    fn from(err: reqwest::Error) -> Self {
        if err.is_timeout() {
            ScanError::NetworkError(format!("请求超时: {}", err))
        } else if err.is_connect() {
            ScanError::NetworkError(format!("连接错误: {}", err))
        } else {
            ScanError::RequestFailed(format!("请求失败: {}", err))
        }
    }
}

impl From<serde_json::Error> for ScanError {
    fn from(err: serde_json::Error) -> Self {
        ScanError::SerializationError(err.to_string())
    }
}

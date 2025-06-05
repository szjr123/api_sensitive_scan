// scanner.rs
use super::{Config, ScanResult, ScanError};
use super::vulnerability::{SensitiveInfoDetector, SensitiveInfoFinding};
use reqwest::Client;
use std::fs;
use std::path::Path;
use std::time::Instant;
use serde::{Serialize, Deserialize};
use indicatif::{ProgressBar, ProgressStyle};
use chrono::Local;
use std::sync::{Arc, Mutex};

// 综合扫描报告结构
#[derive(Debug, Serialize, Deserialize)]
pub struct ComprehensiveScanReport {
    pub basic_results: Vec<ScanResult>,
    pub sensitive_findings: Vec<SensitiveInfoFinding>,
    pub scan_timestamp: String,
    pub scan_duration: u64,
    pub scan_config: ScanConfig,
    // 新增字段
    pub error_count: u32,                // 5xx错误计数
    pub forbidden_urls: Vec<String>,     // 403状态码URL列表
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanConfig {
    pub target: String,
    pub paths_scanned: usize,
}

pub async fn valid_ua(config: &Config) -> Result<String, ScanError> {
    // 验证配置
    config.validate()?;
    
    // 读取UA文件
    let ua_content = fs::read_to_string(&config.user_agent_file) 
        .map_err(|_| ScanError::InvalidConfig("无法读取UA文件".into()))?;
    
    // 创建线程安全的UA队列
    use std::collections::VecDeque;
    use std::sync::Mutex;
    
    let ua_queue = Mutex::new(
        ua_content.lines() 
            .map(|line| line.trim().to_string()) 
            .filter(|ua| !ua.is_empty()) 
            .collect::<VecDeque<_>>()
    );
    
    let mut success = false;
    let mut retry_count = 0;
    let mut current_ua = String::new();
    
    let max_retries = {
        let queue = ua_queue.lock().unwrap();
        queue.len()
    };
    
    // 循环验证直至成功或者全部失败
    while !success && retry_count < max_retries {
        // 获取UA
        {
            let mut queue = ua_queue.lock().unwrap();
            let ua = queue.pop_front().unwrap();
            queue.push_back(ua.clone());
            current_ua = ua;
        }
        
        // 构建headers
        let headers = vec![
            format!("User-Agent: {}", current_ua),
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8".to_string(),
            "Accept-Language: zh-CN,zh;q=0.9,en;q=0.8".to_string(),
            "Accept-Encoding: gzip, deflate, br".to_string(),
            "Connection: keep-alive".to_string(),
        ];
        
        // 发起请求检查返回状态
        match perform_request(config, &headers).await{
            Ok(response) if response.status().is_success() => {
                println!("[成功] UA: {}", current_ua);
                success = true;
            }
            Ok(response) => {
                println!("[失败] UA: {} | 状态: {}", 
                        current_ua, response.status()); 
                retry_count += 1;
            }
            Err(e) => {
                println!("未知错误: {:?}", e);
                retry_count += 1;
            }
        }
    }
    
    if !success {
        return Err(ScanError::RequestFailed("所有UA尝试均失败".into()));
    }
    
    Ok(current_ua)
}

pub async fn run_scan(config: Config) -> Result<ComprehensiveScanReport, ScanError> {
    // 验证配置
    config.validate()?;
    
    println!("正在初始化扫描...");
    
    // 初始化客户端
    let client = build_client(&config)?;
    
    // 加载路径
    let paths = load_paths(&config)?;
    println!("已加载 {} 个API路径", paths.len());
    
    // 执行综合扫描
    let start_time = Instant::now();
    let scan_result = comprehensive_scan(client.clone(), &config, paths).await?;
    
    let _scan_duration = start_time.elapsed().as_secs();
    
    // 生成报告
    save_comprehensive_report(&config.output, &scan_result)?;
    
    // 打印摘要
    print_summary(&scan_result);
    
    Ok(scan_result)
}

async fn perform_request(config: &Config, headers: &[String]) -> Result<reqwest::Response, ScanError> {
    let client = build_client(config)?;
    
    // 构建请求
    let mut req_builder = client.get(&config.target);
    
    // 添加自定义头
    for header in headers {
        if let Some((name, value)) = header.split_once(':') {
            req_builder = req_builder.header(name.trim(), value.trim());
        }
    }
    
    // 添加认证令牌
    if let Some(token) = &config.auth_token {
        req_builder = req_builder.header("Authorization", format!("Bearer {}", token));
    }
    
    // 发送请求
    let response = req_builder.send()
        .await
        .map_err(|e| ScanError::RequestFailed(format!("请求失败: {}", e)))?;
    
    Ok(response)
}

fn build_client(config: &Config) -> Result<Client, ScanError> {
    let mut client_builder = Client::builder()
        .timeout(std::time::Duration::from_secs(config.timeout));
    
    // 配置代理
    if let Some(proxy_url) = &config.proxy {
        let proxy = reqwest::Proxy::all(proxy_url)
            .map_err(|e| ScanError::InvalidConfig(format!("代理配置错误: {}", e)))?;
        client_builder = client_builder.proxy(proxy);
    }
    
    // 创建客户端
    let client = client_builder.build()
        .map_err(|e| ScanError::ClientError(format!("创建HTTP客户端失败: {}", e)))?;
    
    Ok(client)
}

fn load_paths(config: &Config) -> Result<Vec<String>, ScanError> {
    // 从字典文件加载基本路径
    let mut paths = fs::read_to_string(&config.dictionary)
        .map_err(|e| ScanError::IOError(format!("无法读取字典文件: {}", e)))?
        .lines()
        .map(|line| line.trim().to_string())
        .filter(|path| !path.is_empty())
        .collect::<Vec<_>>();

    // 如果指定了包含路径文件，添加这些路径
    if let Some(include_file) = &config.include_paths {
        if include_file.exists() {
            let include_paths = fs::read_to_string(include_file)
                .map_err(|e| ScanError::IOError(format!("无法读取包含路径文件: {}", e)))?
                .lines()
                .map(|line| line.trim().to_string())
                .filter(|path| !path.is_empty())
                .collect::<Vec<_>>();
            
            paths.extend(include_paths);
        }
    }
    
    // 如果指定了排除路径文件，排除这些路径
    if let Some(exclude_file) = &config.exclude_paths {
        if exclude_file.exists() {
            let exclude_paths = fs::read_to_string(exclude_file)
                .map_err(|e| ScanError::IOError(format!("无法读取排除路径文件: {}", e)))?
                .lines()
                .map(|line| line.trim().to_string())
                .filter(|path| !path.is_empty())
                .collect::<Vec<_>>();
            
            paths.retain(|path| !exclude_paths.contains(path));
        }
    }
    
    // 确保路径列表不为空
    if paths.is_empty() {
        return Err(ScanError::InvalidConfig("路径列表为空".into()));
    }
    
    Ok(paths)
}

async fn comprehensive_scan(
    client: Client,
    config: &Config,
    paths: Vec<String>,
) -> Result<ComprehensiveScanReport, ScanError> {
    use futures::stream::{self, StreamExt};
    
    // 创建进度条
    let pb = ProgressBar::new(paths.len() as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} {msg}")
        .unwrap()
        .progress_chars("##-"));
    
    let target_url = &config.target;
    let concurrency = config.concurrency;
    
    // 获取有效的UA
    let user_agent = valid_ua(config).await?;
    
    // 初始化检测器
    let sensitive_detector = SensitiveInfoDetector::new();
    
    // 初始化结果容器
    let mut basic_results = Vec::new();
    let mut sensitive_findings = Vec::new();
    // 使用Arc<Mutex<>>包装forbidden_urls，使其可以在多个异步任务间安全共享
    let forbidden_urls = Arc::new(Mutex::new(Vec::new()));
    let error_count = Arc::new(Mutex::new(0u32));
    
    // 记录整个扫描的开始时间
    let overall_start = Instant::now();
    
    // 创建任务流
    let results = stream::iter(paths.iter().cloned().enumerate())
        .map(|(_idx, path)| {
            let client = client.clone();
            let target = target_url.clone();
            let ua = user_agent.clone();
            let pb = pb.clone();
            let detector = &sensitive_detector;
            let error_counter = Arc::clone(&error_count);
            let forbidden_urls_clone = Arc::clone(&forbidden_urls);
            
            async move {
                // 更新进度条
                pb.set_message(format!("扫描: {}", path));
                
                // 构建URL
                let url = if path.starts_with('/') {
                    format!("{}{}", target.trim_end_matches('/'), path)
                } else {
                    format!("{}/{}", target.trim_end_matches('/'), path)
                };
                
                // 记录开始时间
                let start_time = Instant::now();
                
                // 发送请求
                let scan_result = match client.get(&url)
                    .header("User-Agent", &ua)
                    .header("Authorization", format!("Bearer {}", config.auth_token.as_deref().unwrap_or("")))
                    .header("Accept-Language","zh-CN,zh;q=0.9,en;q=0.8")
                    .header("Connection","keep-alive")
                    .header("Accept","text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
                    .send()
                    .await {
                        Ok(response) => {
                            let status = response.status();
                            let status_code = status.as_u16();
                            let response_time = start_time.elapsed().as_millis() as u64;
                            
                            // 根据状态码进行不同处理
                            match status_code {
                                404 => {
                                    // 404状态码：直接跳过不保留结果
                                    None
                                },
                                403 => {
                                    // 403状态码：只保留URL并返回
                                    // 使用互斥锁安全地修改forbidden_urls
                                    // let mut urls = forbidden_urls_clone.lock().unwrap();
                                    // urls.push(url.clone());
                                    None
                                },
                                500..=599 => {
                                    // 5xx状态码：跳过并记录错误请求+1
                                    let mut counter = error_counter.lock().unwrap();
                                    *counter += 1;
                                    None
                                },
                                200 => {
                                    // 200状态码：只保存有敏感信息泄露的URL和payload以及信息
                                    let body = response.text().await.unwrap_or_default();
                                    let findings = detector.detect(&url, &body);
                                    
                                    if !findings.is_empty() {
                                        // 有敏感信息，保留结果
                                        Some((
                                            ScanResult {
                                                path: path.clone(),
                                                url: url.clone(),
                                                status_code,
                                                content_length: body.len(),
                                                response_time,
                                                found: true,
                                            },
                                            findings
                                        ))
                                    } else {
                                        // 无敏感信息，不保留结果
                                        None
                                    }
                                },
                                _ => {
                                    // 其他状态码：按原有逻辑处理
                                    let body = response.text().await.unwrap_or_default();
                                    let findings = detector.detect(&url, &body);
                                    
                                    Some((
                                        ScanResult {
                                            path: path.clone(),
                                            url: url.clone(),
                                            status_code,
                                            content_length: body.len(),
                                            response_time,
                                            found: status.is_success(),
                                        },
                                        findings
                                    ))
                                }
                            }
                        },
                        Err(e) => {
                            // 请求失败
                            println!("请求失败: {} - {}", url, e);
                            None
                        }
                    };
                
                // 更新进度条
                pb.inc(1);
                scan_result
            }
        })
        .buffer_unordered(concurrency) // 控制并发数
        .collect::<Vec<_>>()
        .await;
    
    // 处理结果
    for result in results {
        if let Some((basic_result, findings)) = result {
            // 添加基本结果
            basic_results.push(basic_result);
            
            // 添加敏感信息发现
            sensitive_findings.extend(findings);
        }
    }
    
    pb.finish_with_message("扫描完成");
    
    // 从Arc<Mutex<>>中获取forbidden_urls
    let forbidden_urls_vec = {
        let urls = forbidden_urls.lock().unwrap();
        urls.clone()
    };
    
    // 创建综合报告
    let report = ComprehensiveScanReport {
        basic_results,
        sensitive_findings,
        scan_timestamp: Local::now().to_string(),
        scan_duration: overall_start.elapsed().as_secs(),  
        scan_config: ScanConfig {
            target: config.target.clone(),
            paths_scanned: paths.len(),
        },
        error_count: *error_count.lock().unwrap(),
        forbidden_urls: forbidden_urls_vec,
    };
    
    Ok(report)
}

fn save_comprehensive_report(output_path: &Path, report: &ComprehensiveScanReport) -> Result<(), ScanError> {
    use serde_json;
    
    // 创建输出目录（如果不存在）
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| ScanError::IOError(format!("无法创建输出目录: {}", e)))?;
    }
    
    // 将结果序列化为JSON
    let json = serde_json::to_string_pretty(report)
        .map_err(|e| ScanError::SerializationError(format!("序列化结果失败: {}", e)))?;
    
    // 写入文件
    fs::write(output_path, json)
        .map_err(|e| ScanError::IOError(format!("写入报告文件失败: {}", e)))?;
    
    println!("扫描报告已保存至: {:?}", output_path);
    
    Ok(())
}

fn print_summary(report: &ComprehensiveScanReport) {
    println!("\n=== 扫描摘要 ===");
    println!("扫描目标: {}", report.scan_config.target);
    println!("扫描路径数: {}", report.scan_config.paths_scanned);
    println!("扫描时间: {}", report.scan_duration);
    println!("扫描时间戳: {}", report.scan_timestamp);
    
    // 状态码统计
    println!("\n状态码统计:");
    println!("  - 5xx错误: {}", report.error_count);
    println!("  - 403禁止访问: {}", report.forbidden_urls.len());
    
    // 基本结果统计
    let success_count = report.basic_results.iter().filter(|r| r.found).count();
    println!("\n基本扫描结果:");
    println!("  - 成功请求: {}/{}", success_count, report.basic_results.len());
    
    // 敏感信息统计
    if !report.sensitive_findings.is_empty() {
        println!("\n敏感信息发现 ({}项):", report.sensitive_findings.len());
        
        // 按类型分组统计
        let mut type_counts = std::collections::HashMap::new();
        for finding in &report.sensitive_findings {
            *type_counts.entry(&finding.info_type).or_insert(0) += 1;
        }
        
        // 按风险评分排序
        let mut risk_types: Vec<_> = type_counts.iter().collect();
        risk_types.sort_by(|a, b| {
            let a_score = report.sensitive_findings.iter()
                .find(|f| &f.info_type == *a.0)
                .map(|f| f.risk_score)
                .unwrap_or(0);
            
            let b_score = report.sensitive_findings.iter()
                .find(|f| &f.info_type == *b.0)
                .map(|f| f.risk_score)
                .unwrap_or(0);
            
            b_score.cmp(&a_score)
        });
        
        for (type_name, count) in risk_types {
            println!("  - {}: {}项", type_name, count);
        }
    } else {
        println!("\n未发现敏感信息");
    }
    
    // 403 URL列表
    if !report.forbidden_urls.is_empty() {
        println!("\n403禁止访问URL ({}项):", report.forbidden_urls.len());
        for (i, url) in report.forbidden_urls.iter().enumerate().take(10) {
            println!("  {}. {}", i+1, url);
        }
        if report.forbidden_urls.len() > 10 {
            println!("  ... 等 {} 项", report.forbidden_urls.len() - 10);
        }
    }
    
    println!("\n详细报告已保存至JSON文件");
}

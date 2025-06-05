use anyhow::Result;
use structopt::StructOpt;
use api_scan::function::scanner::run_scan;
use api_scan::function::config::Config;

#[tokio::main]
async fn main() -> Result<()> {
    // 1. 解析命令行参数
    let config = Config::from_args();
    
    // 2. 执行扫描
    let _results = run_scan(config).await?;
    
    // 3. 显示摘要
    println!("扫描完成！");
    Ok(())
}


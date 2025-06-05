// use super::ScanError;
use serde::{Serialize, Deserialize};
// use std::fs;
// use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
pub struct ScanResult {
    pub path: String,
    pub url: String,
    pub status_code: u16,
    pub content_length: usize,
    pub response_time: u64,
    pub found: bool,
}
use base64::Engine;
use clap::{Parser, ValueEnum};
use csv::Writer;
use futures_util::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use ipnet::IpNet;
use serde::Deserialize;
use sha1::{Digest, Sha1};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tokio_rustls::rustls;
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::{TlsConnector, TlsStream};
use webpki_roots::TLS_SERVER_ROOTS;

const DEFAULT_SPEEDTEST_URL: &str = "https://speed.cloudflare.com/__down?bytes=99999999";
const STAGED_PREFILTER_URL: &str = "https://speed.cloudflare.com/__down?bytes=5000000";

#[derive(Clone, Copy, Debug, ValueEnum)]
enum DownloadMode {
    Staged,
    Legacy,
}

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
enum UploadMode {
    None,
    Api,
}

#[derive(Parser, Debug)]
#[command(name = "cfst-rs")]
struct Args {
    #[arg(long, default_value = "Cloudflare.txt")]
    ip_file: PathBuf,

    #[arg(long)]
    input_csv: Option<PathBuf>,

    #[arg(long, default_value_t = 200)]
    count: usize,

    #[arg(long)]
    final_count: Option<usize>,

    #[arg(long, default_value_t = 200)]
    thread: usize,

    #[arg(long)]
    prefilter_thread: Option<usize>,

    #[arg(long)]
    download_thread: Option<usize>,

    #[arg(long, default_value_t = 1000)]
    delay: u64,

    #[arg(long, default_value_t = 3)]
    latency_samples: usize,

    #[arg(long, default_value_t = 1.0)]
    speed: f64,

    #[arg(long, value_enum, default_value_t = DownloadMode::Staged)]
    download_mode: DownloadMode,

    #[arg(long, default_value = DEFAULT_SPEEDTEST_URL)]
    url: String,

    #[arg(long, default_value = STAGED_PREFILTER_URL)]
    prefilter_url: String,

    #[arg(long, default_value_t = 1_000_000)]
    prefilter_read_bytes: usize,

    #[arg(long, default_value_t = 5_000_000)]
    final_read_bytes: usize,

    #[arg(long, default_value_t = 3.0)]
    connect_timeout: f64,

    #[arg(long, default_value_t = 10.0)]
    download_timeout: f64,

    #[arg(long, default_value = "result.csv")]
    output: PathBuf,

    #[arg(long, value_enum, default_value_t = UploadMode::None)]
    upload: UploadMode,

    #[arg(long, default_value_t = 0)]
    upload_count: usize,

    #[arg(long, default_value_t = 20)]
    upload_per_region: usize,

    #[arg(long, default_value_t = false)]
    clear: bool,

    #[arg(long)]
    deploy_json: Option<PathBuf>,

    #[arg(long, default_value_t = false)]
    probe: bool,

    #[arg(long, default_value_t = 6.0)]
    probe_timeout: f64,

    #[arg(long, default_value = "/?ed=2048")]
    probe_path: String,

    #[arg(long)]
    probe_host: Option<String>,

    #[arg(long)]
    uuid: Option<String>,
}

#[derive(Clone, Debug)]
struct Candidate {
    ip: IpAddr,
    port: u16,
}

#[derive(Clone, Debug)]
struct Measured {
    ip: IpAddr,
    port: u16,
    latency_ms: f64,
    speed_mb_s: f64,
    region_code: String,
    region_name: String,
    country: String,
}

#[derive(Deserialize, Debug)]
struct DeployResult {
    #[serde(default)]
    uuid: String,
    #[serde(default, rename = "deployType")]
    deploy_type_camel: String,
    #[serde(default)]
    deploy_type: String,

    #[serde(default, rename = "apiDomain")]
    api_domain_camel: String,
    #[serde(default)]
    api_domain: String,
    #[serde(default, rename = "probeDomain")]
    probe_domain_camel: String,
    #[serde(default)]
    probe_domain: String,
    #[serde(default, rename = "workerDomain")]
    worker_domain_camel: String,
    #[serde(default)]
    worker_domain: String,
}

#[derive(Clone, Debug)]
struct RuntimeContext {
    uuid: Option<String>,
    probe_host: Option<String>,
    api_domain: Option<String>,
}

#[derive(serde::Serialize)]
struct WorkerUploadItem {
    ip: String,
    port: u16,
    name: String,
    #[serde(rename = "regionCode")]
    region_code: String,
    country: String,
    city: String,
    #[serde(rename = "sourceType")]
    source_type: String,
}

#[derive(Deserialize)]
struct ExistingPreferredResponse {
    #[serde(default)]
    count: usize,
}

#[derive(Deserialize)]
struct UploadResponse {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    added: usize,
    #[serde(default)]
    total: usize,
}

#[derive(Clone, Copy)]
struct AirportInfo {
    name: &'static str,
    country: &'static str,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let _ = rustls::crypto::CryptoProvider::install_default(rustls::crypto::aws_lc_rs::default_provider());

    let requested_final_count = args.final_count.unwrap_or(args.count).min(args.count);
    let latency_thread = derive_latency_thread(args.thread);
    let prefilter_thread = args.prefilter_thread.unwrap_or_else(|| derive_prefilter_thread(args.thread));
    let download_thread = args
        .download_thread
        .unwrap_or_else(|| derive_download_thread(args.thread, requested_final_count));
    let prefilter_speed = derive_prefilter_speed(args.speed);
    let final_stage_pool = derive_final_stage_pool(requested_final_count);
    let connect_timeout = Duration::from_secs_f64(args.connect_timeout.max(0.1));
    let download_timeout = Duration::from_secs_f64(args.download_timeout.max(0.1));
    let probe_timeout = Duration::from_secs_f64(args.probe_timeout.max(0.1));

    let context = resolve_runtime_context(&args)?;
    let probe_host = context.probe_host.clone();
    let uuid = context.uuid.clone();

    let measured = if let Some(input_csv) = args.input_csv.as_ref() {
        let rows = read_result_csv(input_csv)?;
        println!("从 CSV 读取测速结果: {}", rows.len());
        rows
    } else {
        let candidates = load_candidates(&args.ip_file, args.count)?;
        println!("候选 IP 数量: {}", candidates.len());
        let latency_pass = run_latency_stage(
            &candidates,
            latency_thread,
            args.delay,
            connect_timeout,
            args.latency_samples.max(1),
        )
        .await;
        println!("延迟测速通过: {}", latency_pass.len());
        if latency_pass.is_empty() {
            eprintln!("[信息] 延迟测速结果 IP 数量为 0，跳过下载测速。");
            eprintln!("[信息] 完整测速结果 IP 数量为 0，跳过输出结果。");
            eprintln!("❌ 测速失败");
            std::process::exit(1);
        }

        match args.download_mode {
            DownloadMode::Legacy => {
                run_download_stage(
                    &latency_pass,
                    download_thread,
                    &args.url,
                    args.final_read_bytes,
                    args.speed,
                    download_timeout,
                )
                .await
            }
            DownloadMode::Staged => {
                let prefiltered = run_download_stage(
                    &latency_pass,
                    prefilter_thread,
                    &args.prefilter_url,
                    args.prefilter_read_bytes,
                    prefilter_speed,
                    download_timeout,
                )
                .await;
                println!("预筛下载通过: {}", prefiltered.len());
                if prefiltered.is_empty() {
                    eprintln!("❌ 预筛后未找到有效测速结果");
                    std::process::exit(1);
                }
                let mut prefiltered = prefiltered;
                prefiltered.sort_by(|a, b| b.speed_mb_s.total_cmp(&a.speed_mb_s));
                prefiltered.truncate(final_stage_pool.min(prefiltered.len()));

                run_download_stage(
                    &prefiltered,
                    download_thread,
                    &args.url,
                    args.final_read_bytes,
                    args.speed,
                    download_timeout,
                )
                .await
            }
        }
    };
    println!("完整下载通过: {}", measured.len());

    if measured.is_empty() {
        eprintln!("[信息] 完整测速结果 IP 数量为 0，跳过输出结果。");
        eprintln!("❌ 测速失败");
        std::process::exit(1);
    }

    let final_count = args
        .final_count
        .unwrap_or(measured.len())
        .min(measured.len());
    let mut measured = measured;
    measured.sort_by(|a, b| b.speed_mb_s.total_cmp(&a.speed_mb_s));
    measured.truncate(final_count);

    if args.probe {
        let host = probe_host.as_deref().unwrap_or("");
        let uuid = uuid.as_deref().unwrap_or("");
        if host.is_empty() || uuid.is_empty() {
            eprintln!("❌ 缺少 probe 所需的 probe host 或 uuid（可通过 --deploy-json 或 --probe-host/--uuid 提供）");
            std::process::exit(1);
        }

        let path = normalize_path(&args.probe_path);
        let probed = run_probe_stage(&measured, args.thread.min(200).max(1), host, uuid, &path, probe_timeout).await;
        if probed.is_empty() {
            eprintln!("❌ 探测后未找到可连通的IP（请检查网络/VPN/域名或降低筛选条件）");
            std::process::exit(1);
        }
        measured = probed;
    }

    enrich_region_codes(&mut measured, download_thread.min(16).max(1), download_timeout).await;
    sort_measured_by_region_and_speed(&mut measured);

    write_result_csv(&args.output, &measured)?;
    println!("✅ 测速完成！结果已保存到 {}", args.output.display());

    if args.upload == UploadMode::Api {
        upload_to_api(
            &context,
            &measured,
            args.upload_count,
            args.upload_per_region,
            args.clear,
        )
        .await?;
    }
    Ok(())
}

fn normalize_path(path: &str) -> String {
    let p = path.trim();
    if p.is_empty() {
        return "/?ed=2048".to_string();
    }
    if p.starts_with('/') {
        return p.to_string();
    }
    format!("/{}", p)
}

fn derive_prefilter_thread(thread: usize) -> usize {
    thread.clamp(1, 64)
}

fn derive_latency_thread(thread: usize) -> usize {
    thread.clamp(1, 64)
}

fn derive_download_thread(thread: usize, final_count: usize) -> usize {
    thread.clamp(1, 32).min(final_count.max(1))
}

fn derive_prefilter_speed(speed: f64) -> f64 {
    (speed * 0.5).max(0.1)
}

fn derive_final_stage_pool(final_count: usize) -> usize {
    final_count.saturating_mul(3).max(final_count)
}

fn airport_info(region_code: &str) -> Option<AirportInfo> {
    match region_code.trim().to_uppercase().as_str() {
        "HKG" => Some(AirportInfo { name: "香港", country: "中国香港" }),
        "TPE" => Some(AirportInfo { name: "台北", country: "中国台湾" }),
        "NRT" => Some(AirportInfo { name: "东京成田", country: "日本" }),
        "KIX" => Some(AirportInfo { name: "大阪", country: "日本" }),
        "ITM" => Some(AirportInfo { name: "大阪伊丹", country: "日本" }),
        "FUK" => Some(AirportInfo { name: "福冈", country: "日本" }),
        "ICN" => Some(AirportInfo { name: "首尔仁川", country: "韩国" }),
        "SIN" => Some(AirportInfo { name: "新加坡", country: "新加坡" }),
        "BKK" => Some(AirportInfo { name: "曼谷", country: "泰国" }),
        "HAN" => Some(AirportInfo { name: "河内", country: "越南" }),
        "SGN" => Some(AirportInfo { name: "胡志明市", country: "越南" }),
        "MNL" => Some(AirportInfo { name: "马尼拉", country: "菲律宾" }),
        "CGK" => Some(AirportInfo { name: "雅加达", country: "印度尼西亚" }),
        "KUL" => Some(AirportInfo { name: "吉隆坡", country: "马来西亚" }),
        "RGN" => Some(AirportInfo { name: "仰光", country: "缅甸" }),
        "PNH" => Some(AirportInfo { name: "金边", country: "柬埔寨" }),
        "BOM" => Some(AirportInfo { name: "孟买", country: "印度" }),
        "DEL" => Some(AirportInfo { name: "新德里", country: "印度" }),
        "MAA" => Some(AirportInfo { name: "金奈", country: "印度" }),
        "BLR" => Some(AirportInfo { name: "班加罗尔", country: "印度" }),
        "HYD" => Some(AirportInfo { name: "海得拉巴", country: "印度" }),
        "CCU" => Some(AirportInfo { name: "加尔各答", country: "印度" }),
        "SYD" => Some(AirportInfo { name: "悉尼", country: "澳大利亚" }),
        "MEL" => Some(AirportInfo { name: "墨尔本", country: "澳大利亚" }),
        "BNE" => Some(AirportInfo { name: "布里斯班", country: "澳大利亚" }),
        "PER" => Some(AirportInfo { name: "珀斯", country: "澳大利亚" }),
        "AKL" => Some(AirportInfo { name: "奥克兰", country: "新西兰" }),
        "LAX" => Some(AirportInfo { name: "洛杉矶", country: "美国" }),
        "SJC" => Some(AirportInfo { name: "圣何塞", country: "美国" }),
        "SEA" => Some(AirportInfo { name: "西雅图", country: "美国" }),
        "SFO" => Some(AirportInfo { name: "旧金山", country: "美国" }),
        "PDX" => Some(AirportInfo { name: "波特兰", country: "美国" }),
        "SAN" => Some(AirportInfo { name: "圣地亚哥", country: "美国" }),
        "PHX" => Some(AirportInfo { name: "凤凰城", country: "美国" }),
        "LAS" => Some(AirportInfo { name: "拉斯维加斯", country: "美国" }),
        "EWR" => Some(AirportInfo { name: "纽瓦克", country: "美国" }),
        "IAD" => Some(AirportInfo { name: "华盛顿", country: "美国" }),
        "BOS" => Some(AirportInfo { name: "波士顿", country: "美国" }),
        "PHL" => Some(AirportInfo { name: "费城", country: "美国" }),
        "ATL" => Some(AirportInfo { name: "亚特兰大", country: "美国" }),
        "MIA" => Some(AirportInfo { name: "迈阿密", country: "美国" }),
        "MCO" => Some(AirportInfo { name: "奥兰多", country: "美国" }),
        "ORD" => Some(AirportInfo { name: "芝加哥", country: "美国" }),
        "DFW" => Some(AirportInfo { name: "达拉斯", country: "美国" }),
        "IAH" => Some(AirportInfo { name: "休斯顿", country: "美国" }),
        "DEN" => Some(AirportInfo { name: "丹佛", country: "美国" }),
        "MSP" => Some(AirportInfo { name: "明尼阿波利斯", country: "美国" }),
        "DTW" => Some(AirportInfo { name: "底特律", country: "美国" }),
        "STL" => Some(AirportInfo { name: "圣路易斯", country: "美国" }),
        "MCI" => Some(AirportInfo { name: "堪萨斯城", country: "美国" }),
        "YYZ" => Some(AirportInfo { name: "多伦多", country: "加拿大" }),
        "YVR" => Some(AirportInfo { name: "温哥华", country: "加拿大" }),
        "YUL" => Some(AirportInfo { name: "蒙特利尔", country: "加拿大" }),
        "LHR" => Some(AirportInfo { name: "伦敦", country: "英国" }),
        "CDG" => Some(AirportInfo { name: "巴黎", country: "法国" }),
        "FRA" => Some(AirportInfo { name: "法兰克福", country: "德国" }),
        "AMS" => Some(AirportInfo { name: "阿姆斯特丹", country: "荷兰" }),
        "BRU" => Some(AirportInfo { name: "布鲁塞尔", country: "比利时" }),
        "ZRH" => Some(AirportInfo { name: "苏黎世", country: "瑞士" }),
        "VIE" => Some(AirportInfo { name: "维也纳", country: "奥地利" }),
        "MUC" => Some(AirportInfo { name: "慕尼黑", country: "德国" }),
        "DUS" => Some(AirportInfo { name: "杜塞尔多夫", country: "德国" }),
        "HAM" => Some(AirportInfo { name: "汉堡", country: "德国" }),
        "MAD" => Some(AirportInfo { name: "马德里", country: "西班牙" }),
        "BCN" => Some(AirportInfo { name: "巴塞罗那", country: "西班牙" }),
        "MXP" => Some(AirportInfo { name: "米兰", country: "意大利" }),
        "FCO" => Some(AirportInfo { name: "罗马", country: "意大利" }),
        "ATH" => Some(AirportInfo { name: "雅典", country: "希腊" }),
        "LIS" => Some(AirportInfo { name: "里斯本", country: "葡萄牙" }),
        "ARN" => Some(AirportInfo { name: "斯德哥尔摩", country: "瑞典" }),
        "CPH" => Some(AirportInfo { name: "哥本哈根", country: "丹麦" }),
        "OSL" => Some(AirportInfo { name: "奥斯陆", country: "挪威" }),
        "HEL" => Some(AirportInfo { name: "赫尔辛基", country: "芬兰" }),
        "WAW" => Some(AirportInfo { name: "华沙", country: "波兰" }),
        "PRG" => Some(AirportInfo { name: "布拉格", country: "捷克" }),
        "BUD" => Some(AirportInfo { name: "布达佩斯", country: "匈牙利" }),
        "OTP" => Some(AirportInfo { name: "布加勒斯特", country: "罗马尼亚" }),
        "SOF" => Some(AirportInfo { name: "索非亚", country: "保加利亚" }),
        "DXB" => Some(AirportInfo { name: "迪拜", country: "阿联酋" }),
        "TLV" => Some(AirportInfo { name: "特拉维夫", country: "以色列" }),
        "BAH" => Some(AirportInfo { name: "巴林", country: "巴林" }),
        "AMM" => Some(AirportInfo { name: "安曼", country: "约旦" }),
        "KWI" => Some(AirportInfo { name: "科威特", country: "科威特" }),
        "DOH" => Some(AirportInfo { name: "多哈", country: "卡塔尔" }),
        "MCT" => Some(AirportInfo { name: "马斯喀特", country: "阿曼" }),
        "GRU" => Some(AirportInfo { name: "圣保罗", country: "巴西" }),
        "GIG" => Some(AirportInfo { name: "里约热内卢", country: "巴西" }),
        "EZE" => Some(AirportInfo { name: "布宜诺斯艾利斯", country: "阿根廷" }),
        "BOG" => Some(AirportInfo { name: "波哥大", country: "哥伦比亚" }),
        "LIM" => Some(AirportInfo { name: "利马", country: "秘鲁" }),
        "SCL" => Some(AirportInfo { name: "圣地亚哥", country: "智利" }),
        "JNB" => Some(AirportInfo { name: "约翰内斯堡", country: "南非" }),
        "CPT" => Some(AirportInfo { name: "开普敦", country: "南非" }),
        "CAI" => Some(AirportInfo { name: "开罗", country: "埃及" }),
        "LOS" => Some(AirportInfo { name: "拉各斯", country: "尼日利亚" }),
        "NBO" => Some(AirportInfo { name: "内罗毕", country: "肯尼亚" }),
        "ACC" => Some(AirportInfo { name: "阿克拉", country: "加纳" }),
        _ => None,
    }
}

fn country_code_by_name(country: &str) -> Option<&'static str> {
    match country {
        "新加坡" => Some("SG"),
        "中国香港" | "香港" => Some("HK"),
        "日本" => Some("JP"),
        "韩国" => Some("KR"),
        "美国" => Some("US"),
        "德国" => Some("DE"),
        "英国" => Some("GB"),
        "荷兰" => Some("NL"),
        "芬兰" => Some("FI"),
        "瑞典" => Some("SE"),
        "加拿大" => Some("CA"),
        "澳大利亚" => Some("AU"),
        "中国台湾" => Some("TW"),
        "泰国" => Some("TH"),
        "越南" => Some("VN"),
        "菲律宾" => Some("PH"),
        "印度尼西亚" => Some("ID"),
        "马来西亚" => Some("MY"),
        "印度" => Some("IN"),
        "新西兰" => Some("NZ"),
        "法国" => Some("FR"),
        "比利时" => Some("BE"),
        "瑞士" => Some("CH"),
        "奥地利" => Some("AT"),
        "西班牙" => Some("ES"),
        "意大利" => Some("IT"),
        "希腊" => Some("GR"),
        "葡萄牙" => Some("PT"),
        "丹麦" => Some("DK"),
        "挪威" => Some("NO"),
        "波兰" => Some("PL"),
        "捷克" => Some("CZ"),
        "匈牙利" => Some("HU"),
        "罗马尼亚" => Some("RO"),
        "保加利亚" => Some("BG"),
        "阿联酋" => Some("AE"),
        "以色列" => Some("IL"),
        "巴西" => Some("BR"),
        "阿根廷" => Some("AR"),
        "南非" => Some("ZA"),
        "埃及" => Some("EG"),
        _ => None,
    }
}

fn country_flag(country: &str) -> String {
    let Some(code) = country_code_by_name(country) else {
        return String::new();
    };
    code.chars()
        .map(|ch| char::from_u32(127397 + ch as u32).unwrap_or(ch))
        .collect()
}

fn build_geo_label(row: &Measured) -> String {
    let region_code = row.region_code.trim().to_uppercase();
    let region_name = row.region_name.trim();
    let flag = country_flag(&row.country);
    let mut parts = Vec::new();
    if !flag.is_empty() {
        parts.push(flag);
    }
    if !region_name.is_empty() {
        parts.push(region_name.to_string());
    }
    if !region_code.is_empty() {
        parts.push(region_code);
    }
    if parts.is_empty() {
        "UNKNOWN".to_string()
    } else {
        parts.join("-")
    }
}

fn resolve_runtime_context(args: &Args) -> anyhow::Result<RuntimeContext> {
    let mut probe_host = args.probe_host.clone();
    let mut uuid = args.uuid.clone();
    let mut api_domain = None;

    if let Some(path) = args.deploy_json.as_ref() {
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(json) = serde_json::from_str::<DeployResult>(&content) {
                ensure_supported_deploy_target(&json, args.probe)?;
                if uuid.as_deref().unwrap_or("").is_empty() && !json.uuid.trim().is_empty() {
                    uuid = Some(json.uuid.trim().to_string());
                }
                if probe_host.as_deref().unwrap_or("").is_empty() {
                    for value in [
                        json.probe_domain_camel.clone(),
                        json.probe_domain.clone(),
                        json.api_domain_camel.clone(),
                        json.api_domain.clone(),
                        json.worker_domain_camel.clone(),
                        json.worker_domain.clone(),
                    ] {
                        if !value.trim().is_empty() {
                            probe_host = Some(value.trim().to_string());
                            break;
                        }
                    }
                }
                for value in [
                    json.api_domain_camel,
                    json.api_domain,
                    json.worker_domain_camel,
                    json.worker_domain,
                ] {
                    if !value.trim().is_empty() {
                        api_domain = Some(value.trim().to_string());
                        break;
                    }
                }
            }
        }
    }

    Ok(RuntimeContext {
        uuid,
        probe_host,
        api_domain,
    })
}

fn ensure_supported_deploy_target(json: &DeployResult, require_tunnel: bool) -> anyhow::Result<()> {
    let deploy_type = if !json.deploy_type_camel.trim().is_empty() {
        json.deploy_type_camel.trim()
    } else {
        json.deploy_type.trim()
    }
    .to_ascii_lowercase();

    let api_domain = if !json.api_domain_camel.trim().is_empty() {
        json.api_domain_camel.trim()
    } else if !json.api_domain.trim().is_empty() {
        json.api_domain.trim()
    } else if !json.worker_domain_camel.trim().is_empty() {
        json.worker_domain_camel.trim()
    } else {
        json.worker_domain.trim()
    }
    .to_ascii_lowercase();

    let probe_domain = if !json.probe_domain_camel.trim().is_empty() {
        json.probe_domain_camel.trim()
    } else if !json.probe_domain.trim().is_empty() {
        json.probe_domain.trim()
    } else {
        api_domain.as_str()
    }
    .to_ascii_lowercase();

    let uses_pages = deploy_type == "pages"
        || api_domain.ends_with(".pages.dev")
        || probe_domain.ends_with(".pages.dev");
    if uses_pages {
        if require_tunnel {
            anyhow::bail!(
                "deploy-result 使用了 pages.dev 入口：当前 WS+VLESS 严格探测必须使用 Worker 部署，请重新生成 deploy_result.json"
            );
        }
        anyhow::bail!("deploy-result 使用了 pages.dev 入口：请改用 Worker 部署并重新生成 deploy_result.json");
    }
    Ok(())
}

fn load_candidates(path: &Path, count: usize) -> anyhow::Result<Vec<Candidate>> {
    let content = fs::read_to_string(path)?;
    let mut fixed = Vec::new();
    let mut nets = Vec::new();

    for raw in content.lines() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        if let Ok(net) = line.parse::<IpNet>() {
            nets.push(net);
            continue;
        }

        let (host_part, port_part) = line.split_once(':').unwrap_or((line, ""));
        if let Ok(ip) = host_part.parse::<IpAddr>() {
            let port = port_part.parse::<u16>().ok().unwrap_or(443);
            fixed.push(Candidate { ip, port });
        }
    }

    if fixed.len() >= count || nets.is_empty() {
        fixed.truncate(count);
        return Ok(fixed);
    }

    let mut sampled = fixed;
    let mut seen = HashSet::<(IpAddr, u16)>::new();
    for item in &sampled {
        seen.insert((item.ip, item.port));
    }

    let v4_nets: Vec<_> = nets
        .into_iter()
        .filter_map(|net| match net {
            IpNet::V4(v4) => Some(v4),
            IpNet::V6(_) => None,
        })
        .collect();

    if v4_nets.is_empty() {
        return Ok(sampled);
    }

    let remaining = count.saturating_sub(sampled.len());
    let quotas = build_sampling_quotas(&v4_nets, remaining);
    for (net, quota) in v4_nets.iter().zip(quotas.into_iter()) {
        sample_evenly_from_v4_net(*net, quota, &mut sampled, &mut seen);
        if sampled.len() >= count {
            break;
        }
    }

    Ok(sampled)
}

async fn run_latency_stage(
    candidates: &[Candidate],
    concurrency: usize,
    max_latency_ms: u64,
    connect_timeout: Duration,
    latency_samples: usize,
) -> Vec<Measured> {
    let pb = ProgressBar::new(candidates.len() as u64);
    pb.set_style(
        ProgressStyle::with_template("{msg} {wide_bar} {pos}/{len} | 可用: {per_sec}")
            .unwrap()
            .progress_chars("=>-"),
    );
    pb.set_message("开始延迟测速（TCP 443）");

    let semaphore = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut tasks = futures_util::stream::FuturesUnordered::new();

    for candidate in candidates.iter().cloned() {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        tasks.push(tokio::spawn(async move {
            let _permit = permit;
            let latency = measure_tcp_latency(candidate.ip, candidate.port, connect_timeout, latency_samples).await;
            (candidate, latency)
        }));
    }

    let mut ok = Vec::new();
    while let Some(result) = tasks.next().await {
        if let Ok((candidate, latency)) = result {
            if let Some(ms) = latency {
                if ms <= max_latency_ms as f64 {
                    ok.push(Measured {
                        ip: candidate.ip,
                        port: candidate.port,
                        latency_ms: ms,
                        speed_mb_s: 0.0,
                        region_code: String::new(),
                        region_name: String::new(),
                        country: String::new(),
                    });
                }
            }
        }
        pb.inc(1);
    }
    pb.finish_and_clear();
    ok
}

fn build_sampling_quotas(nets: &[ipnet::Ipv4Net], total: usize) -> Vec<usize> {
    if nets.is_empty() || total == 0 {
        return vec![0; nets.len()];
    }

    let hosts: Vec<u64> = nets
        .iter()
        .map(|net| 1u64 << (32 - net.prefix_len()))
        .collect();
    let total_hosts: u128 = hosts.iter().map(|value| *value as u128).sum();
    let mut quotas = vec![0usize; nets.len()];

    for (index, host_count) in hosts.iter().enumerate() {
        let scaled = ((*host_count as u128) * (total as u128)) / total_hosts;
        quotas[index] = scaled.max(1).min(*host_count as u128) as usize;
    }

    let mut allocated: isize = quotas.iter().sum::<usize>() as isize;
    let target = total as isize;

    while allocated > target {
        if let Some((index, _)) = quotas
            .iter()
            .enumerate()
            .filter(|(_, quota)| **quota > 1)
            .max_by_key(|(idx, quota)| (*quota, hosts[*idx]))
        {
            quotas[index] -= 1;
            allocated -= 1;
        } else {
            break;
        }
    }

    while allocated < target {
        if let Some((index, _)) = quotas
            .iter()
            .enumerate()
            .filter(|(idx, quota)| (**quota as u64) < hosts[*idx])
            .max_by_key(|(idx, _)| hosts[*idx])
        {
            quotas[index] += 1;
            allocated += 1;
        } else {
            break;
        }
    }

    quotas
}

fn sample_evenly_from_v4_net(
    net: ipnet::Ipv4Net,
    quota: usize,
    sampled: &mut Vec<Candidate>,
    seen: &mut HashSet<(IpAddr, u16)>,
) {
    if quota == 0 {
        return;
    }

    let network = u32::from(net.network()) as u64;
    let size = 1u64 << (32 - net.prefix_len());
    let limit = quota.min(size as usize);

    for index in 0..limit {
        let offset = (((2 * index + 1) as u64) * size) / ((2 * limit) as u64);
        let ip = IpAddr::V4(Ipv4Addr::from((network + offset) as u32));
        let key = (ip, 443);
        if seen.insert(key) {
            sampled.push(Candidate { ip, port: 443 });
        }
    }
}

async fn measure_tcp_latency(
    ip: IpAddr,
    port: u16,
    connect_timeout: Duration,
    latency_samples: usize,
) -> Option<f64> {
    let mut values = Vec::new();
    for _ in 0..latency_samples.max(1) {
        if let Some(value) = measure_tcp_connect_once(ip, port, connect_timeout).await {
            values.push(value);
        }
    }

    if values.is_empty() {
        return None;
    }

    values.sort_by(|a, b| a.total_cmp(b));
    Some(values[values.len() / 2])
}

async fn measure_tcp_connect_once(ip: IpAddr, port: u16, connect_timeout: Duration) -> Option<f64> {
    let addr = SocketAddr::new(ip, port);
    let started = Instant::now();
    let result = timeout(connect_timeout, TcpStream::connect(addr)).await;
    match result {
        Ok(Ok(stream)) => {
            drop(stream);
            Some(started.elapsed().as_secs_f64() * 1000.0)
        }
        _ => None,
    }
}

async fn run_download_stage(
    candidates: &[Measured],
    concurrency: usize,
    url: &str,
    read_bytes: usize,
    min_speed_mb_s: f64,
    download_timeout: Duration,
) -> Vec<Measured> {
    let effective_timeout = derive_download_timeout(download_timeout, read_bytes, min_speed_mb_s);
    let pb = ProgressBar::new(candidates.len() as u64);
    pb.set_style(
        ProgressStyle::with_template("{msg} {wide_bar} {pos}/{len} | {eta}")
            .unwrap()
            .progress_chars("=>-"),
    );
    pb.set_message(format!(
        "开始下载测速（并发 {}, 读取 {} MB, 超时 {:.0}s）",
        concurrency.max(1),
        read_bytes as f64 / 1_000_000.0,
        effective_timeout.as_secs_f64()
    ));

    let semaphore = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut tasks = futures_util::stream::FuturesUnordered::new();

    for candidate in candidates.iter().cloned() {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let url = url.to_string();
        tasks.push(tokio::spawn(async move {
            let _permit = permit;
            let started = Instant::now();
            let speed = measure_download_speed(candidate.ip, candidate.port, &url, read_bytes, effective_timeout).await;
            let elapsed = started.elapsed().as_secs_f64();
            (candidate, speed, elapsed)
        }));
    }

    let mut ok = Vec::new();
    while let Some(result) = tasks.next().await {
        if let Ok((candidate, speed, elapsed)) = result {
            if let Some(speed_mb_s) = speed {
                if speed_mb_s >= min_speed_mb_s && elapsed > 0.0 {
                    ok.push(Measured {
                        ip: candidate.ip,
                        port: candidate.port,
                        latency_ms: candidate.latency_ms,
                        speed_mb_s,
                        region_code: candidate.region_code,
                        region_name: candidate.region_name,
                        country: candidate.country,
                    });
                }
            }
        }
        pb.inc(1);
    }
    pb.finish_and_clear();
    ok
}

fn derive_download_timeout(base_timeout: Duration, read_bytes: usize, min_speed_mb_s: f64) -> Duration {
    let floor_speed = min_speed_mb_s.max(0.1);
    let read_mb = read_bytes as f64 / 1_000_000.0;
    let expected_seconds = read_mb / floor_speed;
    let padded_seconds = (expected_seconds * 1.5).ceil() + 3.0;
    Duration::from_secs_f64(base_timeout.as_secs_f64().max(padded_seconds))
}

async fn measure_download_speed(
    ip: IpAddr,
    port: u16,
    url: &str,
    read_bytes: usize,
    download_timeout: Duration,
) -> Option<f64> {
    let ip = match ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => return None,
    };

    let mut builder = reqwest::Client::builder()
        .connect_timeout(download_timeout)
        .timeout(download_timeout);
    builder = builder.resolve("speed.cloudflare.com", SocketAddr::new(IpAddr::V4(ip), port));
    let client = builder.build().ok()?;

    let started = Instant::now();
    let response = client.get(url).send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }

    let mut downloaded = 0usize;
    let mut stream = response.bytes_stream();
    while let Some(item) = stream.next().await {
        let chunk = item.ok()?;
        downloaded += chunk.len();
        if downloaded >= read_bytes {
            break;
        }
    }

    let elapsed = started.elapsed().as_secs_f64();
    if elapsed <= 0.0 {
        return None;
    }
    Some(downloaded as f64 / 1_000_000.0 / elapsed)
}

async fn run_probe_stage(
    candidates: &[Measured],
    concurrency: usize,
    host: &str,
    uuid: &str,
    path: &str,
    timeout_duration: Duration,
) -> Vec<Measured> {
    let pb = ProgressBar::new(candidates.len() as u64);
    pb.set_style(
        ProgressStyle::with_template("{msg} {wide_bar} {pos}/{len}")
            .unwrap()
            .progress_chars("=>-"),
    );
    pb.set_message("开始隧道级探测（WS+VLESS+HTTP）");

    let semaphore = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut tasks = futures_util::stream::FuturesUnordered::new();

    for candidate in candidates.iter().cloned() {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let host = host.to_string();
        let uuid = uuid.to_string();
        let path = path.to_string();
        tasks.push(tokio::spawn(async move {
            let _permit = permit;
            let ok = probe_vless_tunnel_via_ip(candidate.ip, candidate.port, &host, &uuid, &path, timeout_duration).await;
            (candidate, ok)
        }));
    }

    let mut ok = Vec::new();
    while let Some(result) = tasks.next().await {
        if let Ok((candidate, passed)) = result {
            if passed {
                ok.push(candidate);
            }
        }
        pb.inc(1);
    }
    pb.finish_and_clear();
    ok
}

async fn probe_vless_tunnel_via_ip(
    ip: IpAddr,
    port: u16,
    host: &str,
    uuid: &str,
    path: &str,
    timeout_duration: Duration,
) -> bool {
    let host = host.trim();
    if host.is_empty() {
        return false;
    }
    let payload = match build_vless_http_probe_payload(uuid) {
        Ok(value) => value,
        Err(_) => return false,
    };

    let websocket_key = base64::engine::general_purpose::STANDARD.encode(rand::random::<[u8; 16]>());
    let accept = {
        let mut hasher = Sha1::new();
        hasher.update(format!("{websocket_key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes());
        base64::engine::general_purpose::STANDARD.encode(hasher.finalize())
    };

    let result = timeout(timeout_duration, async {
        let tcp = TcpStream::connect(SocketAddr::new(ip, port)).await.ok()?;
        let mut tls = tls_connect(tcp, host).await.ok()?;

        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: {websocket_key}\r\nSec-WebSocket-Version: 13\r\nUser-Agent: yx-tools-probe\r\n\r\n"
        );
        tls.write_all(req.as_bytes()).await.ok()?;
        tls.flush().await.ok()?;

        let header = read_http_headers(&mut tls).await.ok()?;
        if !header.starts_with("HTTP/1.1 101") {
            return None;
        }
        if !header.to_ascii_lowercase().contains("upgrade: websocket") {
            return None;
        }
        if !header.to_ascii_lowercase().contains("connection: upgrade") {
            return None;
        }
        if !header.contains(&format!("Sec-WebSocket-Accept: {accept}")) && !header.contains(&format!("sec-websocket-accept: {accept}")) {
            return None;
        }

        let frame = build_websocket_client_frame(&payload, 0x2);
        tls.write_all(&frame).await.ok()?;
        tls.flush().await.ok()?;

        let mut collected = Vec::new();
        let mut stripped_vless_prefix = false;
        let deadline = Instant::now() + timeout_duration;
        while Instant::now() < deadline && collected.len() < 64 * 1024 {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let read = timeout(remaining, read_websocket_frame(&mut tls)).await;
            let frame = match read {
                Ok(Ok(value)) => value,
                _ => break,
            };
            match frame.opcode {
                0x1 | 0x2 => {
                    collected.extend_from_slice(&frame.payload);
                    if !stripped_vless_prefix && collected.len() >= 2 {
                        collected.drain(..2);
                        stripped_vless_prefix = true;
                    }
                    if is_expected_http_probe_response(&collected) {
                        return Some(());
                    }
                }
                0x9 => {
                    let pong = build_websocket_client_frame(&frame.payload, 0xA);
                    let _ = tls.write_all(&pong).await;
                    let _ = tls.flush().await;
                }
                0x8 => break,
                _ => {}
            }
        }
        None
    })
    .await;

    result.ok().flatten().is_some()
}

async fn tls_connect(stream: TcpStream, server_name: &str) -> anyhow::Result<TlsStream<TcpStream>> {
    let root_store = rustls::RootCertStore {
        roots: TLS_SERVER_ROOTS.iter().cloned().collect(),
    };
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let name = ServerName::try_from(server_name.to_string())?;
    Ok(tokio_rustls::TlsStream::Client(connector.connect(name, stream).await?))
}

async fn read_http_headers(stream: &mut TlsStream<TcpStream>) -> io::Result<String> {
    let mut buf = Vec::new();
    let mut scratch = [0u8; 1];
    loop {
        let n = stream.read(&mut scratch).await?;
        if n == 0 {
            break;
        }
        buf.push(scratch[0]);
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            break;
        }
        if buf.len() > 16 * 1024 {
            break;
        }
    }
    Ok(String::from_utf8_lossy(&buf).to_string())
}

fn build_vless_http_probe_payload(uuid: &str) -> anyhow::Result<Vec<u8>> {
    let value = uuid.trim().replace('-', "");
    if value.len() != 32 {
        anyhow::bail!("uuid must be 32 hex chars after removing hyphens");
    }
    let id = hex_to_bytes(&value)?;
    let host = "connectivitycheck.gstatic.com";
    let host_bytes = host.as_bytes();
    let mut request = Vec::new();
    request.extend_from_slice(b"GET /generate_204 HTTP/1.1\r\n");
    request.extend_from_slice(b"Host: connectivitycheck.gstatic.com\r\n");
    request.extend_from_slice(b"User-Agent: yx-tools-probe\r\n");
    request.extend_from_slice(b"Accept: */*\r\n");
    request.extend_from_slice(b"Connection: close\r\n\r\n");

    let mut out = Vec::new();
    out.push(0x00);
    out.extend_from_slice(&id);
    out.push(0x00);
    out.push(0x01);
    out.extend_from_slice(&80u16.to_be_bytes());
    out.push(0x02);
    out.push(host_bytes.len() as u8);
    out.extend_from_slice(host_bytes);
    out.extend_from_slice(&request);
    Ok(out)
}

fn hex_to_bytes(value: &str) -> anyhow::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(value.len() / 2);
    let chars: Vec<char> = value.chars().collect();
    if chars.len() % 2 != 0 {
        anyhow::bail!("hex string length must be even");
    }
    for i in (0..chars.len()).step_by(2) {
        let pair: String = vec![chars[i], chars[i + 1]].into_iter().collect();
        let byte = u8::from_str_radix(&pair, 16)?;
        out.push(byte);
    }
    Ok(out)
}

fn is_expected_http_probe_response(data: &[u8]) -> bool {
    if !(data.starts_with(b"HTTP/1.1 ") || data.starts_with(b"HTTP/1.0 ")) {
        return false;
    }
    let header_end = data.windows(4).position(|w| w == b"\r\n\r\n");
    let header_end = match header_end {
        Some(pos) => pos,
        None => return false,
    };
    let status_line_end = data.windows(2).position(|w| w == b"\r\n").unwrap_or(header_end);
    let status_line = &data[..status_line_end];
    if status_line.windows(5).any(|w| w == b" 204 ") {
        return true;
    }
    if !status_line.windows(5).any(|w| w == b" 200 ") {
        return false;
    }
    let body = &data[header_end + 4..];
    body.windows(b"Example Domain".len()).any(|w| w == b"Example Domain")
}

struct WsFrame {
    opcode: u8,
    payload: Vec<u8>,
}

fn build_websocket_client_frame(payload: &[u8], opcode: u8) -> Vec<u8> {
    let payload_len = payload.len();
    let mut header = Vec::new();
    header.push(0x80 | (opcode & 0x0F));
    let mask_key: [u8; 4] = rand::random();

    if payload_len < 126 {
        header.push(0x80 | payload_len as u8);
    } else if payload_len < 65536 {
        header.push(0x80 | 126);
        header.extend_from_slice(&(payload_len as u16).to_be_bytes());
    } else {
        header.push(0x80 | 127);
        header.extend_from_slice(&(payload_len as u64).to_be_bytes());
    }

    header.extend_from_slice(&mask_key);
    let masked: Vec<u8> = payload
        .iter()
        .enumerate()
        .map(|(idx, byte)| byte ^ mask_key[idx % 4])
        .collect();
    header.extend_from_slice(&masked);
    header
}

async fn read_websocket_frame(stream: &mut TlsStream<TcpStream>) -> io::Result<WsFrame> {
    let mut first_two = [0u8; 2];
    stream.read_exact(&mut first_two).await?;
    let first = first_two[0];
    let second = first_two[1];
    let opcode = first & 0x0F;
    let masked = (second & 0x80) != 0;
    let mut payload_len = (second & 0x7F) as u64;
    if payload_len == 126 {
        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await?;
        payload_len = u16::from_be_bytes(buf) as u64;
    } else if payload_len == 127 {
        let mut buf = [0u8; 8];
        stream.read_exact(&mut buf).await?;
        payload_len = u64::from_be_bytes(buf);
    }
    let mut mask_key = [0u8; 4];
    if masked {
        stream.read_exact(&mut mask_key).await?;
    }
    let mut payload = vec![0u8; payload_len as usize];
    if payload_len > 0 {
        stream.read_exact(&mut payload).await?;
    }
    if masked {
        for (idx, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask_key[idx % 4];
        }
    }
    Ok(WsFrame { opcode, payload })
}

fn read_result_csv(path: &Path) -> anyhow::Result<Vec<Measured>> {
    let mut reader = csv::Reader::from_path(path)?;
    let mut rows = Vec::new();
    for row in reader.deserialize::<std::collections::HashMap<String, String>>() {
        let row = row?;
        let ip_text = row.get("IP 地址").cloned().unwrap_or_default();
        let port_text = row.get("端口").cloned().unwrap_or_else(|| "443".to_string());
        let latency_text = row.get("平均延迟").cloned().unwrap_or_default();
        let speed_text = row
            .get("下载速度(MB/s)")
            .cloned()
            .or_else(|| row.get("下载速度 (MB/s)").cloned())
            .or_else(|| row.get("下载速度").cloned())
            .unwrap_or_default();
        let region_code = row.get("地区码").cloned().unwrap_or_default().trim().to_uppercase();

        let ip = ip_text
            .trim()
            .parse::<IpAddr>()
            .map_err(|err| anyhow::anyhow!("无效 IP `{}`: {}", ip_text, err))?;
        let port = port_text.trim().parse::<u16>().unwrap_or(443);
        let latency_ms = latency_text.trim().parse::<f64>().unwrap_or(0.0);
        let speed_mb_s = speed_text.trim().parse::<f64>().unwrap_or(0.0);
        let info = airport_info(&region_code);
        rows.push(Measured {
            ip,
            port,
            latency_ms,
            speed_mb_s,
            region_name: info.map(|item| item.name.to_string()).unwrap_or_else(|| region_code.clone()),
            country: info.map(|item| item.country.to_string()).unwrap_or_default(),
            region_code,
        });
    }
    Ok(rows)
}

async fn enrich_region_codes(measured: &mut [Measured], concurrency: usize, timeout_duration: Duration) {
    let semaphore = Arc::new(Semaphore::new(concurrency.max(1)));
    let mut tasks = futures_util::stream::FuturesUnordered::new();

    for (index, row) in measured.iter().enumerate() {
        if !row.region_code.trim().is_empty() {
            continue;
        }
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let ip = row.ip;
        let port = row.port;
        tasks.push(tokio::spawn(async move {
            let _permit = permit;
            let colo = fetch_region_code(ip, port, timeout_duration).await;
            (index, colo)
        }));
    }

    while let Some(result) = tasks.next().await {
        if let Ok((index, Some(code))) = result {
            let info = airport_info(&code);
            measured[index].region_code = code.clone();
            measured[index].region_name = info.map(|item| item.name.to_string()).unwrap_or(code);
            measured[index].country = info.map(|item| item.country.to_string()).unwrap_or_default();
        }
    }
}

async fn fetch_region_code(ip: IpAddr, port: u16, timeout_duration: Duration) -> Option<String> {
    let ip = match ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => return None,
    };
    let mut builder = reqwest::Client::builder()
        .connect_timeout(timeout_duration)
        .timeout(timeout_duration);
    builder = builder.resolve("speed.cloudflare.com", SocketAddr::new(IpAddr::V4(ip), port));
    let client = builder.build().ok()?;
    let text = client
        .get("https://speed.cloudflare.com/cdn-cgi/trace")
        .send()
        .await
        .ok()?
        .text()
        .await
        .ok()?;
    text.lines()
        .find_map(|line| line.strip_prefix("colo="))
        .map(|value| value.trim().to_uppercase())
}

fn write_result_csv(path: &Path, measured: &[Measured]) -> anyhow::Result<()> {
    let mut writer = Writer::from_path(path)?;
    let headers = ["显示名称", "IP 地址", "端口", "平均延迟", "下载速度(MB/s)", "地区码"];
    writer.write_record(headers)?;
    for (index, row) in measured.iter().enumerate() {
        writer.write_record([
            build_node_name(row, index + 1),
            row.ip.to_string(),
            row.port.to_string(),
            format!("{:.2}", row.latency_ms),
            format!("{:.2}", row.speed_mb_s),
            row.region_code.clone(),
        ])?;
    }
    writer.flush()?;
    Ok(())
}

fn region_group_key(row: &Measured) -> String {
    let region_code = row.region_code.trim();
    if !region_code.is_empty() {
        return region_code.to_uppercase();
    }
    let region_name = row.region_name.trim();
    if !region_name.is_empty() {
        return region_name.to_string();
    }
    "UNKNOWN".to_string()
}

fn region_display_key(row: &Measured) -> String {
    build_geo_label(row)
}

fn build_node_name(row: &Measured, index: usize) -> String {
    format!("{}-{:02}", build_geo_label(row), index)
}

fn sort_measured_by_region_and_speed(measured: &mut [Measured]) {
    measured.sort_by(|a, b| {
        let region_order = region_group_key(a).cmp(&region_group_key(b));
        if region_order != std::cmp::Ordering::Equal {
            return region_order;
        }
        let speed_order = b.speed_mb_s.total_cmp(&a.speed_mb_s);
        if speed_order != std::cmp::Ordering::Equal {
            return speed_order;
        }
        a.latency_ms.total_cmp(&b.latency_ms)
    });
}

fn build_worker_upload_items(measured: &[Measured]) -> Vec<WorkerUploadItem> {
    measured
        .iter()
        .enumerate()
        .map(|(index, row)| WorkerUploadItem {
            ip: row.ip.to_string(),
            port: row.port,
            name: build_node_name(row, index + 1),
            region_code: row.region_code.clone(),
            country: row.country.clone(),
            city: row.region_name.clone(),
            source_type: "preferred".to_string(),
        })
        .collect()
}

async fn upload_to_api(
    context: &RuntimeContext,
    measured: &[Measured],
    upload_count: usize,
    upload_per_region: usize,
    clear_existing: bool,
) -> anyhow::Result<()> {
    let api_domain = context
        .api_domain
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("缺少 API 域名，请通过 --deploy-json 提供 workerDomain/apiDomain"))?;
    let uuid = context
        .uuid
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| anyhow::anyhow!("缺少 uuid，请通过 --deploy-json 或 --uuid 提供"))?;

    if measured.is_empty() {
        anyhow::bail!("没有可上传的测速结果");
    }

    let api_url = format!("https://{api_domain}/{uuid}/api/preferred-ips");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()?;

    println!("\n{}", "=".repeat(70));
    println!(" 命令行模式：Cloudflare Workers API 上报");
    println!("{}", "=".repeat(70));
    println!("\n🔍 正在检查现有优选IP...");

    let mut should_clear = false;
    match client.get(&api_url).send().await {
        Ok(response) if response.status().is_success() => {
            if let Ok(body) = response.json::<ExistingPreferredResponse>().await {
                if body.count > 0 {
                    println!("⚠️  发现已存在 {} 个优选IP", body.count);
                    if clear_existing {
                        should_clear = true;
                    } else {
                        println!("💡 提示: 使用 --clear 参数可以在上传前清空现有IP，避免IP累积");
                    }
                } else {
                    println!("✅ 当前无数据，将直接添加");
                }
            }
        }
        Ok(response) => {
            println!("⚠️  无法获取现有数据状态 (HTTP {})", response.status());
            should_clear = clear_existing;
        }
        Err(error) => {
            println!("⚠️  检查现有数据失败: {}", error);
            should_clear = clear_existing;
        }
    }

    let unique_best_ips = select_unique_best_ips(measured, upload_count, upload_per_region);
    println!("\n📊 正在读取测速结果...");
    println!(
        "✅ 找到 {} 个测速结果，按地区分组后将上传 {} 个（每地区最多 {} 个）",
        measured.len(),
        unique_best_ips.len(),
        upload_per_region.max(1)
    );
    for (region, count) in summarize_region_counts(&unique_best_ips) {
        println!("   - {}: {}", region, count);
    }

    if should_clear {
        println!("\n🗑️  正在清空现有数据...");
        match client
            .delete(&api_url)
            .json(&serde_json::json!({ "all": true }))
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => {
                println!("✅ 现有数据已清空");
            }
            Ok(response) => {
                println!("⚠️  清空失败 (HTTP {})，继续尝试添加...", response.status());
            }
            Err(error) => {
                println!("⚠️  清空操作失败: {}，继续尝试添加...", error);
            }
        }
    }

    println!("\n🚀 开始批量上报优选IP...");
    let payload = build_worker_upload_items(&unique_best_ips);
    let response = client
        .post(&api_url)
        .json(&payload)
        .send()
        .await?;

    if !response.status().is_success() {
        anyhow::bail!("上传失败，HTTP {}", response.status());
    }

    let result = response.json::<UploadResponse>().await.unwrap_or(UploadResponse {
        success: false,
        added: 0,
        total: 0,
    });

    println!("\n{}", "=".repeat(70));
    println!(" ✅ 批量上报完成！");
    println!("{}", "=".repeat(70));
    println!("  ✅ 成功添加: {}", result.added);
    println!("  📊 总计: {}", result.total.max(result.added));
    println!("{}", "=".repeat(70));

    if !result.success && result.added == 0 {
        println!("⚠️  服务端未返回 success=true，请手动核对 preferred-ips 接口结果");
    }

    Ok(())
}

fn summarize_region_counts(measured: &[Measured]) -> Vec<(String, usize)> {
    let mut counts = BTreeMap::new();
    for row in measured {
        let key = region_display_key(row);
        *counts.entry(key).or_insert(0usize) += 1;
    }
    counts.into_iter().collect()
}

fn select_unique_best_ips(measured: &[Measured], upload_count: usize, upload_per_region: usize) -> Vec<Measured> {
    let mut ordered = measured.to_vec();
    sort_measured_by_region_and_speed(&mut ordered);
    let mut seen = HashSet::new();
    let mut per_region_counts = BTreeMap::new();
    let mut rows = Vec::new();
    let per_region_limit = upload_per_region.max(1);
    for row in &ordered {
        let key = (row.ip, row.port);
        if !seen.insert(key) {
            continue;
        }
        let region_key = region_group_key(row);
        let region_count = per_region_counts.entry(region_key).or_insert(0usize);
        if *region_count >= per_region_limit {
            continue;
        }
        rows.push(row.clone());
        *region_count += 1;
        if upload_count > 0 && rows.len() >= upload_count {
            break;
        }
    }
    rows
}

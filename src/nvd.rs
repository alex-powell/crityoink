use std::collections::HashMap;
use std::io::Read;
use std::time::{Duration, Instant};

use chrono::{DateTime, NaiveDateTime, Utc};
use serde::Deserialize;

use crate::db::{Configuration, StoredCve, StoredDb};
use crate::error::{Error, Result};

pub const NVD_BASE: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";
pub const USER_AGENT: &str = "crityoink/0.1 (+https://github.com/alex-powell/crityoink)";
pub const RESULTS_PER_PAGE: u32 = 2000;
/// NVD no-key budget is 5 requests / 30s (6s). Pad to ~7.5s between requests.
pub const DEFAULT_MIN_INTERVAL: Duration = Duration::from_millis(7500);

/// Separate query streams: NVD allows one severity filter per request.
/// Inventory CPE strings are never added to these URLs.
pub const QUERY_STREAMS: &[(&str, &str)] = &[
    ("cvssV3Severity", "CRITICAL"),
    ("cvssV3Severity", "HIGH"),
    ("cvssV4Severity", "CRITICAL"),
    ("cvssV4Severity", "HIGH"),
    ("cvssV2Severity", "HIGH"),
];

/// NVD lastMod windows are capped at 120 consecutive days.
pub const LAST_MOD_MAX_DAYS: i64 = 120;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncDecision {
    FullRebuild {
        reason: &'static str,
    },
    Incremental {
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    },
}

/// Format a UTC timestamp the way NVD 2.0 lastMod parameters expect.
pub fn format_last_mod(dt: DateTime<Utc>) -> String {
    dt.format("%Y-%m-%dT%H:%M:%S%.3f").to_string()
}

/// Parse a stored watermark or NVD lastMod timestamp.
pub fn parse_last_mod(s: &str) -> Option<DateTime<Utc>> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    for fmt in [
        "%Y-%m-%dT%H:%M:%S%.3f",
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%dT%H:%M:%S",
    ] {
        if let Ok(naive) = NaiveDateTime::parse_from_str(s, fmt) {
            return Some(naive.and_utc());
        }
    }
    None
}

pub fn last_mod_window_too_old(start: DateTime<Utc>, end: DateTime<Utc>) -> bool {
    end.signed_duration_since(start).num_seconds() > LAST_MOD_MAX_DAYS * 86_400
}

pub fn decide_sync(
    existing: Option<&StoredDb>,
    force_full: bool,
    now: DateTime<Utc>,
) -> SyncDecision {
    if force_full {
        return SyncDecision::FullRebuild { reason: "--full" };
    }
    let Some(db) = existing else {
        return SyncDecision::FullRebuild {
            reason: "no local database",
        };
    };
    if !db.has_incremental_watermark() {
        return SyncDecision::FullRebuild {
            reason: "missing last-mod watermark or old schema",
        };
    }
    let Some(start) = parse_last_mod(&db.last_mod_end) else {
        return SyncDecision::FullRebuild {
            reason: "unreadable last-mod watermark",
        };
    };
    if start > now {
        return SyncDecision::FullRebuild {
            reason: "last-mod watermark is in the future",
        };
    }
    if last_mod_window_too_old(start, now) {
        return SyncDecision::FullRebuild {
            reason: "last-mod watermark is older than NVD's 120-day window",
        };
    }
    SyncDecision::Incremental { start, end: now }
}

#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub retry_after: Option<String>,
    pub body: String,
}

pub trait HttpGet {
    fn get(&self, url: &str) -> Result<HttpResponse>;
}

pub trait Sleeper {
    fn sleep(&self, duration: Duration);
}

pub struct StdSleeper;

impl Sleeper for StdSleeper {
    fn sleep(&self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

pub struct UreqClient;

impl HttpGet for UreqClient {
    fn get(&self, url: &str) -> Result<HttpResponse> {
        let result = ureq::get(url)
            .set("User-Agent", USER_AGENT)
            .set("Accept", "application/json")
            .timeout(Duration::from_secs(120))
            .call();
        match result {
            Ok(resp) => read_ureq(resp),
            Err(ureq::Error::Status(_code, resp)) => read_ureq(resp),
            Err(e) => Err(Error::Http(e.to_string())),
        }
    }
}

fn read_ureq(resp: ureq::Response) -> Result<HttpResponse> {
    let status = resp.status();
    let retry_after = resp.header("retry-after").map(str::to_string);
    let mut body = String::new();
    resp.into_reader().read_to_string(&mut body)?;
    Ok(HttpResponse {
        status,
        retry_after,
        body,
    })
}

#[derive(Debug, Deserialize)]
struct ApiPage {
    #[serde(default, rename = "resultsPerPage")]
    results_per_page: u32,
    #[serde(default, rename = "totalResults")]
    total_results: u32,
    #[serde(default)]
    vulnerabilities: Vec<ApiItem>,
}

#[derive(Debug, Deserialize)]
struct ApiItem {
    cve: ApiCve,
}

#[derive(Debug, Deserialize)]
struct ApiCve {
    id: String,
    #[serde(default)]
    published: Option<String>,
    #[serde(default, rename = "vulnStatus")]
    vuln_status: Option<String>,
    #[serde(default)]
    descriptions: Vec<ApiDesc>,
    #[serde(default)]
    metrics: Option<ApiMetrics>,
    #[serde(default)]
    configurations: Vec<Configuration>,
}

#[derive(Debug, Deserialize)]
struct ApiDesc {
    #[serde(default)]
    lang: Option<String>,
    #[serde(default)]
    value: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct ApiMetrics {
    #[serde(default, rename = "cvssMetricV31")]
    v31: Vec<ApiCvssMetric>,
    #[serde(default, rename = "cvssMetricV30")]
    v30: Vec<ApiCvssMetric>,
    #[serde(default, rename = "cvssMetricV40")]
    v40: Vec<ApiCvssMetric>,
    #[serde(default, rename = "cvssMetricV2")]
    v2: Vec<ApiCvssMetric>,
}

#[derive(Debug, Deserialize)]
struct ApiCvssMetric {
    #[serde(default, rename = "type")]
    metric_type: Option<String>,
    #[serde(default, rename = "cvssData")]
    cvss_data: Option<ApiCvssData>,
    #[serde(default, rename = "baseSeverity")]
    base_severity: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct ApiCvssData {
    #[serde(default, rename = "baseScore")]
    base_score: Option<f64>,
    #[serde(default, rename = "baseSeverity")]
    base_severity: Option<String>,
}

pub fn build_url(
    sev_param: &str,
    sev_value: &str,
    start_index: u32,
    results_per_page: u32,
) -> String {
    format!(
        "{NVD_BASE}?{sev_param}={sev_value}&noRejected&startIndex={start_index}&resultsPerPage={results_per_page}"
    )
}

/// lastMod delta: no severity filter and no `noRejected`, so demotions and Rejected CVEs appear.
pub fn build_last_mod_url(
    last_mod_start: &str,
    last_mod_end: &str,
    start_index: u32,
    results_per_page: u32,
) -> String {
    format!(
        "{NVD_BASE}?lastModStartDate={last_mod_start}&lastModEndDate={last_mod_end}&startIndex={start_index}&resultsPerPage={results_per_page}"
    )
}

pub fn url_is_inventory_free(url: &str) -> bool {
    let lower = url.to_ascii_lowercase();
    !lower.contains("cpename=")
        && !lower.contains("keywordsearch=")
        && !lower.contains("virtualmatchstring=")
        && !lower.contains("keyword=")
}

pub fn sleep_needed(elapsed: Option<Duration>, min_interval: Duration) -> Option<Duration> {
    if min_interval.is_zero() {
        return None;
    }
    match elapsed {
        None => None,
        Some(e) if e >= min_interval => None,
        Some(e) => Some(min_interval.saturating_sub(e)),
    }
}

pub fn parse_retry_after(header: Option<&str>) -> Option<Duration> {
    let raw = header?.trim();
    if raw.is_empty() {
        return None;
    }
    if let Ok(secs) = raw.parse::<u64>() {
        return Some(Duration::from_secs(secs.min(600)));
    }
    if let Ok(dt) = DateTime::parse_from_rfc2822(raw) {
        let wait = dt.with_timezone(&Utc) - Utc::now();
        let secs = wait.num_seconds();
        if secs > 0 {
            return Some(Duration::from_secs((secs as u64).min(600)));
        }
        return Some(Duration::from_secs(1));
    }
    None
}

pub fn retry_wait(retry_after: Option<&str>, attempt: u32, min_interval: Duration) -> Duration {
    let fallback =
        min_interval.saturating_mul(2u32.saturating_pow(attempt.saturating_sub(1).min(4)));
    parse_retry_after(retry_after)
        .unwrap_or(fallback)
        .max(min_interval)
}

pub fn is_rejected_status(status: &str) -> bool {
    let s = status.trim().to_ascii_lowercase();
    s == "rejected" || s == "rejected-related" || s.starts_with("rejected")
}

fn first_metric(items: &[ApiCvssMetric]) -> Option<&ApiCvssMetric> {
    items
        .iter()
        .find(|m| m.metric_type.as_deref() == Some("Primary"))
        .or_else(|| items.first())
}

fn extract_severity(metrics: &ApiMetrics) -> (String, Option<f64>) {
    for (key, items) in [
        ("v31", metrics.v31.as_slice()),
        ("v30", metrics.v30.as_slice()),
        ("v40", metrics.v40.as_slice()),
        ("v2", metrics.v2.as_slice()),
    ] {
        let Some(item) = first_metric(items) else {
            continue;
        };
        let data = item.cvss_data.as_ref();
        let score = data.and_then(|d| d.base_score);
        let mut sev = data
            .and_then(|d| d.base_severity.clone())
            .or_else(|| item.base_severity.clone())
            .unwrap_or_else(|| "UNKNOWN".into())
            .to_ascii_uppercase();
        if key == "v2" && (sev.is_empty() || sev == "UNKNOWN") {
            sev = match score {
                None => "UNKNOWN".into(),
                Some(s) if s >= 7.0 => "HIGH".into(),
                Some(s) if s >= 4.0 => "MEDIUM".into(),
                _ => "LOW".into(),
            };
        }
        return (sev, score);
    }
    ("UNKNOWN".into(), None)
}

fn english_description(descs: &[ApiDesc]) -> String {
    for d in descs {
        if d.lang.as_deref() == Some("en") {
            let v = d.value.as_deref().unwrap_or("").trim();
            return v.chars().take(280).collect();
        }
    }
    String::new()
}

fn published_date(raw: &Option<String>) -> String {
    raw.as_deref().unwrap_or("").chars().take(10).collect()
}

pub fn ingest_cve_json(value: &serde_json::Value) -> Result<Option<StoredCve>> {
    let cve: ApiCve = serde_json::from_value(value.clone())?;
    Ok(ingest_api_cve(&cve))
}

enum DeltaAction {
    /// High/Critical, not Rejected, has configurations → insert or replace.
    Upsert(StoredCve),
    /// Rejected or dropped below High/Critical → delete from the local DB if present.
    Remove(String),
    /// Empty id or no configurations: do not insert and do not delete.
    Ignore,
}

fn delta_action(cve: &ApiCve) -> DeltaAction {
    if cve.id.trim().is_empty() {
        return DeltaAction::Ignore;
    }
    if is_rejected_status(cve.vuln_status.as_deref().unwrap_or("")) {
        return DeltaAction::Remove(cve.id.clone());
    }
    let (severity, score) =
        extract_severity(cve.metrics.as_ref().unwrap_or(&ApiMetrics::default()));
    if !crate::cpe::is_high_or_critical(&severity) {
        return DeltaAction::Remove(cve.id.clone());
    }
    if cve.configurations.is_empty() {
        return DeltaAction::Ignore;
    }
    DeltaAction::Upsert(StoredCve {
        id: cve.id.clone(),
        severity,
        score,
        published: published_date(&cve.published),
        description: english_description(&cve.descriptions),
        configurations: cve.configurations.clone(),
    })
}

fn ingest_api_cve(cve: &ApiCve) -> Option<StoredCve> {
    match delta_action(cve) {
        DeltaAction::Upsert(stored) => Some(stored),
        DeltaAction::Remove(_) | DeltaAction::Ignore => None,
    }
}

fn apply_delta_cve(by_id: &mut HashMap<String, StoredCve>, cve: &ApiCve) {
    match delta_action(cve) {
        DeltaAction::Upsert(stored) => {
            by_id.insert(stored.id.clone(), stored);
        }
        DeltaAction::Remove(id) => {
            by_id.remove(&id);
        }
        DeltaAction::Ignore => {}
    }
}

struct RateLimitState {
    min_interval: Duration,
    last: Option<Instant>,
}

impl RateLimitState {
    fn before_request<S: Sleeper>(&mut self, sleeper: &S) {
        if let Some(wait) = sleep_needed(self.last.map(|t| t.elapsed()), self.min_interval) {
            sleeper.sleep(wait);
        }
    }

    fn after_request(&mut self) {
        self.last = Some(Instant::now());
    }
}

fn request_with_retry<H: HttpGet, S: Sleeper>(
    http: &H,
    sleeper: &S,
    url: &str,
    rl: &mut RateLimitState,
) -> Result<HttpResponse> {
    const MAX_ATTEMPTS: u32 = 6;
    let mut last_err = Error::Http("NVD request failed".into());
    for attempt in 1..=MAX_ATTEMPTS {
        rl.before_request(sleeper);
        let resp = match http.get(url) {
            Ok(r) => r,
            Err(e) => {
                rl.after_request();
                last_err = e;
                if attempt == MAX_ATTEMPTS {
                    break;
                }
                sleeper.sleep(retry_wait(None, attempt, rl.min_interval));
                continue;
            }
        };
        rl.after_request();
        if resp.status == 200 {
            return Ok(resp);
        }
        if resp.status == 429 || resp.status == 403 {
            let wait = retry_wait(resp.retry_after.as_deref(), attempt, rl.min_interval);
            eprintln!(
                "NVD returned {} — waiting {}s then retrying (attempt {attempt}/{MAX_ATTEMPTS})",
                resp.status,
                wait.as_secs()
            );
            sleeper.sleep(wait);
            last_err = Error::Http(format!("NVD HTTP {}", resp.status));
            continue;
        }
        if resp.status == 400 {
            return Ok(resp);
        }
        if (500..600).contains(&resp.status) && attempt < MAX_ATTEMPTS {
            sleeper.sleep(retry_wait(None, attempt, rl.min_interval));
            last_err = Error::Http(format!("NVD HTTP {}", resp.status));
            continue;
        }
        return Err(Error::Http(format!("NVD HTTP {} for {url}", resp.status)));
    }
    Err(last_err)
}

pub fn sync_from_nvd<H: HttpGet, S: Sleeper>(
    http: &H,
    sleeper: &S,
    min_interval: Duration,
) -> Result<StoredDb> {
    sync_from_nvd_with_page_size(http, sleeper, min_interval, RESULTS_PER_PAGE)
}

pub fn sync_from_nvd_with_page_size<H: HttpGet, S: Sleeper>(
    http: &H,
    sleeper: &S,
    min_interval: Duration,
    results_per_page: u32,
) -> Result<StoredDb> {
    let mut by_id: HashMap<String, StoredCve> = HashMap::new();
    let mut rl = RateLimitState {
        min_interval,
        last: None,
    };

    for (param, value) in QUERY_STREAMS {
        eprintln!("Fetching {param}={value} from NVD (High/Critical only; no inventory sent)…");
        let mut start = 0u32;
        loop {
            let url = build_url(param, value, start, results_per_page);
            debug_assert!(url_is_inventory_free(&url));
            let resp = request_with_retry(http, sleeper, &url, &mut rl)?;
            if resp.status == 400 {
                eprintln!("NVD rejected stream {param}={value} (HTTP 400); skipping this stream.");
                break;
            }
            if resp.status != 200 {
                return Err(Error::Http(format!("NVD HTTP {} for {url}", resp.status)));
            }
            let page: ApiPage = serde_json::from_str(&resp.body).map_err(|e| {
                Error::msg(format!(
                    "Failed to parse NVD JSON at startIndex={start}: {e}"
                ))
            })?;
            eprintln!(
                "  startIndex={start} resultsPerPage={} totalResults={}",
                page.results_per_page, page.total_results
            );
            for item in &page.vulnerabilities {
                if let Some(stored) = ingest_api_cve(&item.cve) {
                    by_id.entry(stored.id.clone()).or_insert(stored);
                }
            }
            if page.vulnerabilities.is_empty() {
                break;
            }
            let step = if page.results_per_page > 0 {
                page.results_per_page
            } else {
                page.vulnerabilities.len() as u32
            };
            start = start.saturating_add(step);
            if start >= page.total_results {
                break;
            }
        }
    }

    let now = Utc::now();
    let synced_at = now.to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let last_mod_end = format_last_mod(now);
    let vulns: Vec<StoredCve> = by_id.into_values().collect();
    Ok(StoredDb::from_cves(
        NVD_BASE.to_string(),
        synced_at,
        last_mod_end,
        vulns,
    ))
}

pub fn refresh_from_nvd<H: HttpGet, S: Sleeper>(
    http: &H,
    sleeper: &S,
    min_interval: Duration,
    existing: Option<StoredDb>,
    force_full: bool,
) -> Result<StoredDb> {
    refresh_from_nvd_with_page_size(
        http,
        sleeper,
        min_interval,
        RESULTS_PER_PAGE,
        existing,
        force_full,
        Utc::now(),
    )
}

pub fn refresh_from_nvd_with_page_size<H: HttpGet, S: Sleeper>(
    http: &H,
    sleeper: &S,
    min_interval: Duration,
    results_per_page: u32,
    existing: Option<StoredDb>,
    force_full: bool,
    now: DateTime<Utc>,
) -> Result<StoredDb> {
    match decide_sync(existing.as_ref(), force_full, now) {
        SyncDecision::FullRebuild { reason } => {
            eprintln!(
                "Full rebuild ({reason}): High/Critical severity streams, Rejected skipped, no inventory sent."
            );
            sync_from_nvd_with_page_size(http, sleeper, min_interval, results_per_page)
        }
        SyncDecision::Incremental { start, end } => {
            let start_s = format_last_mod(start);
            let end_s = format_last_mod(end);
            eprintln!(
                "Incremental lastMod sync {start_s} .. {end_s} (all statuses/severities so demotions and Rejected are visible; no inventory sent)."
            );
            let Some(existing) = existing else {
                eprintln!(
                    "Incremental selected without a loaded DB; falling back to full rebuild."
                );
                return sync_from_nvd_with_page_size(http, sleeper, min_interval, results_per_page);
            };
            match sync_incremental_with_page_size(
                http,
                sleeper,
                min_interval,
                results_per_page,
                existing,
                start,
                end,
            ) {
                Ok(db) => Ok(db),
                Err(e) if last_mod_window_rejected(&e) => {
                    eprintln!(
                        "NVD rejected the lastMod window ({e}); falling back to full rebuild."
                    );
                    sync_from_nvd_with_page_size(http, sleeper, min_interval, results_per_page)
                }
                Err(e) => Err(e),
            }
        }
    }
}

fn last_mod_window_rejected(err: &Error) -> bool {
    matches!(err, Error::Http(msg) if msg.contains("lastMod") && msg.contains("400"))
}

pub fn sync_incremental_with_page_size<H: HttpGet, S: Sleeper>(
    http: &H,
    sleeper: &S,
    min_interval: Duration,
    results_per_page: u32,
    existing: StoredDb,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
) -> Result<StoredDb> {
    let mut by_id: HashMap<String, StoredCve> = existing
        .vulnerabilities
        .into_iter()
        .map(|c| (c.id.clone(), c))
        .collect();
    let mut rl = RateLimitState {
        min_interval,
        last: None,
    };
    let start_s = format_last_mod(start);
    let end_s = format_last_mod(end);
    eprintln!("Fetching lastMod {start_s} .. {end_s} from NVD…");
    let mut start_index = 0u32;
    loop {
        let url = build_last_mod_url(&start_s, &end_s, start_index, results_per_page);
        debug_assert!(url_is_inventory_free(&url));
        debug_assert!(!url.contains("noRejected"));
        let resp = request_with_retry(http, sleeper, &url, &mut rl)?;
        if resp.status == 400 {
            return Err(Error::Http(format!(
                "NVD lastMod window rejected (HTTP 400) for {url}"
            )));
        }
        if resp.status != 200 {
            return Err(Error::Http(format!("NVD HTTP {} for {url}", resp.status)));
        }
        let page: ApiPage = serde_json::from_str(&resp.body).map_err(|e| {
            Error::msg(format!(
                "Failed to parse NVD JSON at startIndex={start_index}: {e}"
            ))
        })?;
        eprintln!(
            "  startIndex={start_index} resultsPerPage={} totalResults={}",
            page.results_per_page, page.total_results
        );
        for item in &page.vulnerabilities {
            apply_delta_cve(&mut by_id, &item.cve);
        }
        if page.vulnerabilities.is_empty() {
            break;
        }
        let step = if page.results_per_page > 0 {
            page.results_per_page
        } else {
            page.vulnerabilities.len() as u32
        };
        start_index = start_index.saturating_add(step);
        if start_index >= page.total_results {
            break;
        }
    }

    let synced_at = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let vulns: Vec<StoredCve> = by_id.into_values().collect();
    Ok(StoredDb::from_cves(
        NVD_BASE.to_string(),
        synced_at,
        end_s,
        vulns,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    struct RecSleeper {
        sleeps: RefCell<Vec<Duration>>,
    }
    impl Sleeper for RecSleeper {
        fn sleep(&self, duration: Duration) {
            self.sleeps.borrow_mut().push(duration);
        }
    }

    struct SeqClient {
        urls: Mutex<Vec<String>>,
        responses: Mutex<VecDeque<HttpResponse>>,
        by_prefix: Mutex<HashMap<String, VecDeque<HttpResponse>>>,
    }

    impl SeqClient {
        fn new(responses: Vec<HttpResponse>) -> Self {
            Self {
                urls: Mutex::new(Vec::new()),
                responses: Mutex::new(responses.into()),
                by_prefix: Mutex::new(HashMap::new()),
            }
        }
    }

    impl HttpGet for SeqClient {
        fn get(&self, url: &str) -> Result<HttpResponse> {
            self.urls.lock().unwrap().push(url.to_string());
            let mut map = self.by_prefix.lock().unwrap();
            for (prefix, q) in map.iter_mut() {
                if url.contains(prefix.as_str()) {
                    if let Some(r) = q.pop_front() {
                        return Ok(r);
                    }
                }
            }
            if let Some(r) = self.responses.lock().unwrap().pop_front() {
                return Ok(r);
            }
            Ok(HttpResponse {
                status: 200,
                retry_after: None,
                body: empty_page(),
            })
        }
    }

    fn empty_page() -> String {
        r#"{"resultsPerPage":0,"startIndex":0,"totalResults":0,"format":"NVD_CVE","version":"2.0","vulnerabilities":[]}"#.into()
    }

    fn page_json(start: u32, total: u32, cves: &str) -> String {
        format!(
            r#"{{"resultsPerPage":1,"startIndex":{start},"totalResults":{total},"format":"NVD_CVE","version":"2.0","vulnerabilities":[{cves}]}}"#
        )
    }

    fn high_cve_json(id: &str, status: &str, severity: &str, score: f64, product: &str) -> String {
        format!(
            r#"{{"cve":{{"id":"{id}","published":"2021-12-10T00:00:00.000","vulnStatus":"{status}","descriptions":[{{"lang":"en","value":"desc {id}"}}],"metrics":{{"cvssMetricV31":[{{"type":"Primary","cvssData":{{"baseScore":{score},"baseSeverity":"{severity}"}}}}]}},"configurations":[{{"nodes":[{{"operator":"OR","negate":false,"cpeMatch":[{{"vulnerable":true,"criteria":"cpe:2.3:a:acme:{product}:1.0:*:*:*:*:*:*:*"}}]}}]}}]}}}}"#
        )
    }

    #[test]
    fn default_interval_is_six_seconds_plus_padding() {
        assert!(DEFAULT_MIN_INTERVAL >= Duration::from_secs(7));
        assert!(DEFAULT_MIN_INTERVAL <= Duration::from_secs(8));
    }

    #[test]
    fn sleep_needed_first_request_is_none() {
        assert_eq!(sleep_needed(None, Duration::from_secs(8)), None);
    }

    #[test]
    fn sleep_needed_pads_remaining_interval() {
        assert_eq!(
            sleep_needed(Some(Duration::from_secs(2)), Duration::from_millis(7500)),
            Some(Duration::from_millis(5500))
        );
        assert_eq!(
            sleep_needed(Some(Duration::from_secs(8)), Duration::from_millis(7500)),
            None
        );
    }

    #[test]
    fn retry_after_integer_and_cap() {
        assert_eq!(parse_retry_after(Some("12")), Some(Duration::from_secs(12)));
        assert_eq!(
            parse_retry_after(Some("9999")),
            Some(Duration::from_secs(600))
        );
        assert!(parse_retry_after(Some("nope")).is_none());
    }

    #[test]
    fn urls_never_include_inventory_or_cpe_list() {
        let url = build_url("cvssV3Severity", "HIGH", 0, 2000);
        assert!(url.starts_with(NVD_BASE));
        assert!(url.contains("cvssV3Severity=HIGH"));
        assert!(url.contains("noRejected"));
        assert!(url.contains("startIndex=0"));
        assert!(url.contains("resultsPerPage=2000"));
        assert!(url_is_inventory_free(&url));
        assert!(!url.to_ascii_lowercase().contains("openssl"));
        assert!(!url.to_ascii_lowercase().contains("log4j"));
    }

    #[test]
    fn ingest_skips_rejected_and_medium() {
        let rejected: serde_json::Value = serde_json::from_str(&high_cve_json(
            "CVE-2020-REJ",
            "Rejected",
            "HIGH",
            7.5,
            "foo",
        ))
        .unwrap();
        let cve = rejected.get("cve").unwrap().clone();
        assert!(ingest_cve_json(&cve).unwrap().is_none());

        let related: serde_json::Value = serde_json::from_str(&high_cve_json(
            "CVE-2020-REJR",
            "Rejected-related",
            "CRITICAL",
            9.8,
            "foo",
        ))
        .unwrap();
        assert!(ingest_cve_json(related.get("cve").unwrap())
            .unwrap()
            .is_none());

        let medium: serde_json::Value = serde_json::from_str(&high_cve_json(
            "CVE-2020-MED",
            "Analyzed",
            "MEDIUM",
            5.0,
            "foo",
        ))
        .unwrap();
        assert!(ingest_cve_json(medium.get("cve").unwrap())
            .unwrap()
            .is_none());

        let high: serde_json::Value = serde_json::from_str(&high_cve_json(
            "CVE-2020-HI",
            "Analyzed",
            "HIGH",
            7.5,
            "foo",
        ))
        .unwrap();
        let stored = ingest_cve_json(high.get("cve").unwrap()).unwrap().unwrap();
        assert_eq!(stored.id, "CVE-2020-HI");
        assert_eq!(stored.severity, "HIGH");
    }

    #[test]
    fn sync_paginates_filters_and_dedupes() {
        let sleeper = RecSleeper {
            sleeps: RefCell::new(Vec::new()),
        };
        let client = SeqClient::new(vec![]);
        {
            let mut map = client.by_prefix.lock().unwrap();
            map.insert(
                "cvssV3Severity=HIGH".into(),
                VecDeque::from([
                    HttpResponse {
                        status: 200,
                        retry_after: None,
                        body: page_json(
                            0,
                            2,
                            &high_cve_json("CVE-2020-0001", "Analyzed", "HIGH", 7.5, "one"),
                        ),
                    },
                    HttpResponse {
                        status: 200,
                        retry_after: None,
                        body: page_json(
                            1,
                            2,
                            &high_cve_json("CVE-2020-0002", "Rejected", "HIGH", 7.5, "two"),
                        ),
                    },
                ]),
            );
            map.insert(
                "cvssV3Severity=CRITICAL".into(),
                VecDeque::from([HttpResponse {
                    status: 200,
                    retry_after: None,
                    body: page_json(
                        0,
                        1,
                        &high_cve_json("CVE-2020-0001", "Analyzed", "HIGH", 7.5, "one"),
                    ),
                }]),
            );
        }
        let db = sync_from_nvd_with_page_size(&client, &sleeper, Duration::ZERO, 1).unwrap();
        assert_eq!(db.counts.total_stored, 1);
        assert_eq!(db.counts.high, 1);
        assert_eq!(db.vulnerabilities[0].id, "CVE-2020-0001");
        assert_eq!(db.source, NVD_BASE);
        assert!(!db.synced_at.is_empty());
        assert!(!db.last_mod_end.is_empty());
        assert_eq!(db.schema_version, crate::db::SCHEMA_VERSION);
        let urls = client.urls.lock().unwrap();
        assert!(urls.iter().all(|u| url_is_inventory_free(u)));
        assert!(urls.iter().any(|u| u.contains("startIndex=1")));
        assert!(urls.iter().all(|u| u.contains("noRejected")));
        assert!(!urls.iter().any(|u| u.contains("noRejected=")));
    }

    #[test]
    fn respects_429_retry_after_then_succeeds() {
        let sleeper = RecSleeper {
            sleeps: RefCell::new(Vec::new()),
        };
        let client = SeqClient::new(vec![
            HttpResponse {
                status: 429,
                retry_after: Some("3".into()),
                body: String::new(),
            },
            HttpResponse {
                status: 200,
                retry_after: None,
                body: empty_page(),
            },
        ]);
        let _db =
            sync_from_nvd_with_page_size(&client, &sleeper, Duration::from_millis(1), 1).unwrap();
        let sleeps = sleeper.sleeps.borrow();
        assert!(
            sleeps.iter().any(|d| *d == Duration::from_secs(3)),
            "expected Retry-After sleep, got {sleeps:?}"
        );
    }

    #[test]
    fn rate_limiter_records_padding_between_requests() {
        let sleeper = RecSleeper {
            sleeps: RefCell::new(Vec::new()),
        };
        let mut rl = RateLimitState {
            min_interval: Duration::from_millis(7500),
            last: None,
        };
        rl.before_request(&sleeper);
        rl.after_request();
        rl.before_request(&sleeper);
        let sleeps = sleeper.sleeps.borrow();
        assert_eq!(sleeps.len(), 1);
        assert!(sleeps[0] >= Duration::from_millis(7400));
        assert!(sleeps[0] <= Duration::from_millis(7500));
    }

    fn apply_one(map: &mut HashMap<String, StoredCve>, json: &str) {
        let v: serde_json::Value = serde_json::from_str(json).unwrap();
        let cve: ApiCve = serde_json::from_value(v.get("cve").unwrap().clone()).unwrap();
        apply_delta_cve(map, &cve);
    }

    fn seed_map(ids: &[(&str, &str)]) -> HashMap<String, StoredCve> {
        ids.iter()
            .map(|(id, sev)| {
                let score = if *sev == "CRITICAL" { 9.8 } else { 7.5 };
                let json = high_cve_json(id, "Analyzed", sev, score, "foo");
                let v: serde_json::Value = serde_json::from_str(&json).unwrap();
                let stored = ingest_cve_json(v.get("cve").unwrap()).unwrap().unwrap();
                (stored.id.clone(), stored)
            })
            .collect()
    }

    fn utc(s: &str) -> DateTime<Utc> {
        parse_last_mod(s).unwrap()
    }

    #[test]
    fn last_mod_format_roundtrip() {
        let dt = utc("2026-05-01T12:34:56.000");
        assert_eq!(format_last_mod(dt), "2026-05-01T12:34:56.000");
        assert_eq!(
            parse_last_mod("2026-05-01T12:34:56Z").unwrap(),
            utc("2026-05-01T12:34:56.000")
        );
        assert!(parse_last_mod("").is_none());
        assert!(parse_last_mod("bogus").is_none());
    }

    #[test]
    fn incremental_last_mod_url_has_no_severity_or_norejected() {
        let url = build_last_mod_url(
            "2026-01-01T00:00:00.000",
            "2026-01-02T00:00:00.000",
            0,
            2000,
        );
        assert!(url.starts_with(NVD_BASE));
        assert!(url.contains("lastModStartDate=2026-01-01T00:00:00.000"));
        assert!(url.contains("lastModEndDate=2026-01-02T00:00:00.000"));
        assert!(url.contains("startIndex=0"));
        assert!(url.contains("resultsPerPage=2000"));
        assert!(!url.contains("noRejected"));
        assert!(!url.contains("cvssV3Severity"));
        assert!(!url.contains("cvssV4Severity"));
        assert!(!url.contains("cvssV2Severity"));
        assert!(url_is_inventory_free(&url));
    }

    #[test]
    fn delta_upserts_still_high_or_critical() {
        let mut map = seed_map(&[("CVE-2020-KEEP", "HIGH")]);
        apply_one(
            &mut map,
            &high_cve_json("CVE-2020-KEEP", "Analyzed", "CRITICAL", 9.8, "updated"),
        );
        let stored = map.get("CVE-2020-KEEP").expect("still present");
        assert_eq!(stored.severity, "CRITICAL");
        assert_eq!(stored.score, Some(9.8));
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn delta_inserts_upgrade_to_high_critical() {
        let mut map = seed_map(&[("CVE-2020-KEEP", "HIGH")]);
        apply_one(
            &mut map,
            &high_cve_json("CVE-2020-NEW", "Analyzed", "HIGH", 7.5, "newp"),
        );
        assert!(map.contains_key("CVE-2020-NEW"));
        assert!(map.contains_key("CVE-2020-KEEP"));
        assert_eq!(map["CVE-2020-NEW"].severity, "HIGH");
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn delta_removes_rejected() {
        let mut map = seed_map(&[
            ("CVE-2020-REJ", "HIGH"),
            ("CVE-2020-REJR", "CRITICAL"),
            ("CVE-2020-KEEP", "HIGH"),
        ]);
        apply_one(
            &mut map,
            &high_cve_json("CVE-2020-REJ", "Rejected", "HIGH", 7.5, "foo"),
        );
        apply_one(
            &mut map,
            &high_cve_json("CVE-2020-REJR", "Rejected-related", "CRITICAL", 9.8, "foo"),
        );
        assert!(!map.contains_key("CVE-2020-REJ"));
        assert!(!map.contains_key("CVE-2020-REJR"));
        assert!(map.contains_key("CVE-2020-KEEP"));
    }

    #[test]
    fn delta_removes_demotion_below_high() {
        let mut map = seed_map(&[("CVE-2020-DEM", "CRITICAL"), ("CVE-2020-KEEP", "HIGH")]);
        apply_one(
            &mut map,
            &high_cve_json("CVE-2020-DEM", "Analyzed", "MEDIUM", 5.0, "foo"),
        );
        assert!(!map.contains_key("CVE-2020-DEM"));
        assert!(map.contains_key("CVE-2020-KEEP"));
    }

    #[test]
    fn delta_leaves_unrelated_local_entries() {
        let mut map = seed_map(&[("CVE-2020-STAY", "HIGH"), ("CVE-2020-KEEP", "HIGH")]);
        apply_one(
            &mut map,
            &high_cve_json("CVE-2020-KEEP", "Analyzed", "HIGH", 8.1, "foo"),
        );
        assert!(map.contains_key("CVE-2020-STAY"));
        assert_eq!(map["CVE-2020-KEEP"].score, Some(8.1));
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn decide_sync_full_rebuild_fallbacks() {
        let now = utc("2026-06-01T00:00:00.000");
        assert!(matches!(
            decide_sync(None, false, now),
            SyncDecision::FullRebuild {
                reason: "no local database"
            }
        ));
        assert!(matches!(
            decide_sync(None, true, now),
            SyncDecision::FullRebuild { reason: "--full" }
        ));

        let mut db = StoredDb::from_cves(
            NVD_BASE.into(),
            "2026-05-01T00:00:00Z".into(),
            "2026-05-01T00:00:00.000".into(),
            vec![],
        );
        assert!(matches!(
            decide_sync(Some(&db), true, now),
            SyncDecision::FullRebuild { reason: "--full" }
        ));

        db.last_mod_end.clear();
        assert!(matches!(
            decide_sync(Some(&db), false, now),
            SyncDecision::FullRebuild { .. }
        ));

        db.last_mod_end = "2026-05-01T00:00:00.000".into();
        db.schema_version = 1;
        assert!(matches!(
            decide_sync(Some(&db), false, now),
            SyncDecision::FullRebuild { .. }
        ));

        db.schema_version = crate::db::SCHEMA_VERSION;
        db.last_mod_end = "not-a-date".into();
        assert!(matches!(
            decide_sync(Some(&db), false, now),
            SyncDecision::FullRebuild { .. }
        ));

        db.last_mod_end = "2026-01-01T00:00:00.000".into();
        assert!(matches!(
            decide_sync(Some(&db), false, now),
            SyncDecision::FullRebuild {
                reason: "last-mod watermark is older than NVD's 120-day window"
            }
        ));

        db.last_mod_end = "2026-05-01T00:00:00.000".into();
        match decide_sync(Some(&db), false, now) {
            SyncDecision::Incremental { start, end } => {
                assert_eq!(format_last_mod(start), "2026-05-01T00:00:00.000");
                assert_eq!(end, now);
            }
            other => panic!("expected incremental, got {other:?}"),
        }
    }

    #[test]
    fn incremental_sync_merges_pages_and_sets_watermark() {
        let sleeper = RecSleeper {
            sleeps: RefCell::new(Vec::new()),
        };
        let existing = StoredDb::from_cves(
            NVD_BASE.into(),
            "2026-01-01T00:00:00Z".into(),
            "2026-01-01T00:00:00.000".into(),
            seed_map(&[
                ("CVE-2020-KEEP", "HIGH"),
                ("CVE-2020-REJ", "HIGH"),
                ("CVE-2020-DEM", "CRITICAL"),
                ("CVE-2020-STAY", "HIGH"),
            ])
            .into_values()
            .collect(),
        );
        let start = utc("2026-01-01T00:00:00.000");
        let end = utc("2026-01-10T00:00:00.000");
        let client = SeqClient::new(vec![
            HttpResponse {
                status: 200,
                retry_after: None,
                body: page_json(
                    0,
                    4,
                    &high_cve_json("CVE-2020-KEEP", "Analyzed", "CRITICAL", 9.8, "keep"),
                ),
            },
            HttpResponse {
                status: 200,
                retry_after: None,
                body: page_json(
                    1,
                    4,
                    &high_cve_json("CVE-2020-NEW", "Analyzed", "HIGH", 7.5, "newp"),
                ),
            },
            HttpResponse {
                status: 200,
                retry_after: None,
                body: page_json(
                    2,
                    4,
                    &high_cve_json("CVE-2020-REJ", "Rejected", "HIGH", 7.5, "rej"),
                ),
            },
            HttpResponse {
                status: 200,
                retry_after: None,
                body: page_json(
                    3,
                    4,
                    &high_cve_json("CVE-2020-DEM", "Analyzed", "LOW", 2.0, "dem"),
                ),
            },
        ]);
        let db = sync_incremental_with_page_size(
            &client,
            &sleeper,
            Duration::ZERO,
            1,
            existing,
            start,
            end,
        )
        .unwrap();
        let ids: Vec<_> = db.vulnerabilities.iter().map(|v| v.id.as_str()).collect();
        assert!(ids.contains(&"CVE-2020-KEEP"));
        assert!(ids.contains(&"CVE-2020-NEW"));
        assert!(ids.contains(&"CVE-2020-STAY"));
        assert!(!ids.contains(&"CVE-2020-REJ"));
        assert!(!ids.contains(&"CVE-2020-DEM"));
        let keep = db
            .vulnerabilities
            .iter()
            .find(|v| v.id == "CVE-2020-KEEP")
            .unwrap();
        assert_eq!(keep.severity, "CRITICAL");
        assert_eq!(db.last_mod_end, "2026-01-10T00:00:00.000");
        assert_eq!(db.counts.total_stored, 3);
        let urls = client.urls.lock().unwrap();
        assert!(urls.iter().all(|u| u.contains("lastModStartDate=")));
        assert!(urls.iter().all(|u| u.contains("lastModEndDate=")));
        assert!(urls.iter().all(|u| !u.contains("noRejected")));
        assert!(urls.iter().all(|u| !u.contains("cvssV3Severity")));
        assert!(urls.iter().all(|u| url_is_inventory_free(u)));
        assert!(urls.iter().any(|u| u.contains("startIndex=1")));
    }

    #[test]
    fn refresh_force_full_uses_severity_streams() {
        let sleeper = RecSleeper {
            sleeps: RefCell::new(Vec::new()),
        };
        let existing = StoredDb::from_cves(
            NVD_BASE.into(),
            "2026-05-01T00:00:00Z".into(),
            "2026-05-01T00:00:00.000".into(),
            vec![],
        );
        let now = utc("2026-05-15T00:00:00.000");
        let client = SeqClient::new(vec![]);
        let db = refresh_from_nvd_with_page_size(
            &client,
            &sleeper,
            Duration::ZERO,
            1,
            Some(existing),
            true,
            now,
        )
        .unwrap();
        let urls = client.urls.lock().unwrap();
        assert!(urls.iter().any(|u| u.contains("cvssV3Severity")));
        assert!(urls.iter().all(|u| !u.contains("lastModStartDate")));
        assert!(urls.iter().all(|u| u.contains("noRejected")));
        assert!(!db.last_mod_end.is_empty());
    }

    #[test]
    fn refresh_without_db_is_full_rebuild() {
        let sleeper = RecSleeper {
            sleeps: RefCell::new(Vec::new()),
        };
        let now = utc("2026-05-15T00:00:00.000");
        let client = SeqClient::new(vec![]);
        let _db =
            refresh_from_nvd_with_page_size(&client, &sleeper, Duration::ZERO, 1, None, false, now)
                .unwrap();
        let urls = client.urls.lock().unwrap();
        assert!(urls.iter().any(|u| u.contains("cvssV3Severity")));
        assert!(urls.iter().all(|u| !u.contains("lastModStartDate")));
    }

    #[test]
    fn refresh_with_watermark_uses_last_mod() {
        let sleeper = RecSleeper {
            sleeps: RefCell::new(Vec::new()),
        };
        let existing = StoredDb::from_cves(
            NVD_BASE.into(),
            "2026-05-01T00:00:00Z".into(),
            "2026-05-01T00:00:00.000".into(),
            vec![],
        );
        let now = utc("2026-05-15T00:00:00.000");
        let client = SeqClient::new(vec![HttpResponse {
            status: 200,
            retry_after: None,
            body: empty_page(),
        }]);
        let db = refresh_from_nvd_with_page_size(
            &client,
            &sleeper,
            Duration::ZERO,
            1,
            Some(existing),
            false,
            now,
        )
        .unwrap();
        let urls = client.urls.lock().unwrap();
        assert!(urls
            .iter()
            .all(|u| u.contains("lastModStartDate=2026-05-01T00:00:00.000")));
        assert!(urls
            .iter()
            .all(|u| u.contains("lastModEndDate=2026-05-15T00:00:00.000")));
        assert!(urls.iter().all(|u| !u.contains("noRejected")));
        assert_eq!(db.last_mod_end, "2026-05-15T00:00:00.000");
    }
}

use std::collections::HashMap;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
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
    let body = resp.into_string().unwrap_or_default();
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

fn ingest_api_cve(cve: &ApiCve) -> Option<StoredCve> {
    if cve.id.trim().is_empty() {
        return None;
    }
    if is_rejected_status(cve.vuln_status.as_deref().unwrap_or("")) {
        return None;
    }
    let (severity, score) =
        extract_severity(cve.metrics.as_ref().unwrap_or(&ApiMetrics::default()));
    if !crate::cpe::is_high_or_critical(&severity) {
        return None;
    }
    if cve.configurations.is_empty() {
        return None;
    }
    Some(StoredCve {
        id: cve.id.clone(),
        severity,
        score,
        published: published_date(&cve.published),
        description: english_description(&cve.descriptions),
        configurations: cve.configurations.clone(),
    })
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

    let synced_at = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let vulns: Vec<StoredCve> = by_id.into_values().collect();
    Ok(StoredDb::from_cves(NVD_BASE.to_string(), synced_at, vulns))
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
        let urls = client.urls.lock().unwrap();
        assert!(urls.iter().all(|u| url_is_inventory_free(u)));
        assert!(urls.iter().any(|u| u.contains("startIndex=1")));
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
}

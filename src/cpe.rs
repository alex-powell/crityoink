use std::cmp::Ordering;

use crate::csv_inv::InventoryRow;
use crate::db::{Configuration, CpeMatch, Node, StoredCve};

#[derive(Debug, Clone, PartialEq)]
pub struct Hit {
    pub cve_id: String,
    pub severity: String,
    pub score: Option<f64>,
    pub inventory: InventoryRow,
    pub matched_criteria: String,
    pub published: String,
    pub description: String,
}

pub fn severity_rank(sev: &str) -> u8 {
    match sev.to_ascii_uppercase().as_str() {
        "CRITICAL" => 4,
        "HIGH" => 3,
        "MEDIUM" => 2,
        "LOW" => 1,
        _ => 0,
    }
}

pub fn is_high_or_critical(sev: &str) -> bool {
    matches!(sev.to_ascii_uppercase().as_str(), "HIGH" | "CRITICAL")
}

/// Parse CPE 2.3 (`cpe:2.3:…`) or legacy 2.2 (`cpe:/…`) into 13 fields.
pub fn split_cpe(cpe: &str) -> Option<Vec<String>> {
    let raw = cpe.trim();
    if raw.starts_with("cpe:2.3:") {
        let mut parts: Vec<String> = raw.split(':').map(|s| s.to_string()).collect();
        if parts.len() < 6 {
            return None;
        }
        while parts.len() < 13 {
            parts.push("*".to_string());
        }
        return Some(parts);
    }
    if let Some(body) = raw.strip_prefix("cpe:/") {
        let bits: Vec<String> = body.split(':').map(|s| s.to_string()).collect();
        if bits.len() < 3 {
            return None;
        }
        let mut parts = vec!["cpe".to_string(), "2.3".to_string()];
        parts.extend(bits);
        while parts.len() < 13 {
            parts.push("*".to_string());
        }
        return Some(parts);
    }
    None
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum VerTok {
    Num(u64),
    Alpha(String),
}

fn version_tuple(ver: &str) -> Vec<VerTok> {
    if matches!(ver, "*" | "-" | "") {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut chars = ver.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_ascii_digit() {
            let mut n = 0u64;
            while let Some(&d) = chars.peek() {
                if d.is_ascii_digit() {
                    n = n
                        .saturating_mul(10)
                        .saturating_add(u64::from(d as u8 - b'0'));
                    chars.next();
                } else {
                    break;
                }
            }
            out.push(VerTok::Num(n));
        } else if c.is_ascii_alphabetic() {
            let mut s = String::new();
            while let Some(&d) = chars.peek() {
                if d.is_ascii_alphabetic() {
                    s.push(d.to_ascii_lowercase());
                    chars.next();
                } else {
                    break;
                }
            }
            out.push(VerTok::Alpha(s));
        } else {
            chars.next();
        }
    }
    out
}

pub fn version_cmp(a: &str, b: &str) -> Ordering {
    let mut ta = version_tuple(a);
    let mut tb = version_tuple(b);
    let n = ta.len().max(tb.len());
    ta.resize(n, VerTok::Num(0));
    tb.resize(n, VerTok::Num(0));
    ta.cmp(&tb)
}

pub fn version_in_range(inv_ver: &str, m: &CpeMatch) -> bool {
    let crit_ver = split_cpe(&m.criteria)
        .and_then(|p| p.get(5).cloned())
        .unwrap_or_else(|| "*".to_string());
    let has_range = m.version_start_including.is_some()
        || m.version_start_excluding.is_some()
        || m.version_end_including.is_some()
        || m.version_end_excluding.is_some();

    if inv_ver == "*" || inv_ver == "-" {
        return true;
    }

    if has_range || crit_ver == "*" || crit_ver == "-" {
        if let Some(v) = &m.version_start_including {
            if version_cmp(inv_ver, v) == Ordering::Less {
                return false;
            }
        }
        if let Some(v) = &m.version_start_excluding {
            if version_cmp(inv_ver, v) != Ordering::Greater {
                return false;
            }
        }
        if let Some(v) = &m.version_end_including {
            if version_cmp(inv_ver, v) == Ordering::Greater {
                return false;
            }
        }
        if let Some(v) = &m.version_end_excluding {
            if version_cmp(inv_ver, v) != Ordering::Less {
                return false;
            }
        }
        return true;
    }

    version_cmp(inv_ver, &crit_ver) == Ordering::Equal
}

pub fn cpe_identity_match(inv: &InventoryRow, criteria: &str) -> bool {
    let Some(parts) = split_cpe(criteria) else {
        return false;
    };
    let part = parts[2].to_ascii_lowercase();
    let vendor = parts[3].to_ascii_lowercase();
    let product = parts[4].to_ascii_lowercase();
    if part != "*" && part != inv.part {
        return false;
    }
    if vendor != "*" && vendor != inv.vendor {
        return false;
    }
    if product != "*" && product != inv.product {
        return false;
    }
    true
}

fn cpe_match_hits(inv: &InventoryRow, m: &CpeMatch) -> bool {
    m.vulnerable && cpe_identity_match(inv, &m.criteria) && version_in_range(&inv.version, m)
}

pub fn node_matches(inv: &InventoryRow, node: &Node) -> bool {
    let child_hits: Vec<bool> = node.children.iter().map(|c| node_matches(inv, c)).collect();
    let own_hits: Vec<bool> = node
        .cpe_match
        .iter()
        .map(|m| cpe_match_hits(inv, m))
        .collect();
    let bits: Vec<bool> = child_hits.into_iter().chain(own_hits).collect();
    if bits.is_empty() {
        return false;
    }
    let op = node
        .operator
        .as_deref()
        .unwrap_or("OR")
        .to_ascii_uppercase();
    let result = if op == "AND" {
        bits.iter().all(|b| *b)
    } else {
        bits.iter().any(|b| *b)
    };
    if node.negate.unwrap_or(false) {
        !result
    } else {
        result
    }
}

pub fn first_matching_criteria(inv: &InventoryRow, configs: &[Configuration]) -> Option<String> {
    for cfg in configs {
        for node in &cfg.nodes {
            if node_matches(inv, node) {
                for m in &node.cpe_match {
                    if cpe_match_hits(inv, m) {
                        return Some(m.criteria.clone());
                    }
                }
                return Some("(configuration match)".to_string());
            }
        }
    }
    None
}

pub fn match_all(inventory: &[InventoryRow], cves: &[StoredCve]) -> Vec<Hit> {
    let mut hits = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for cve in cves {
        if !is_high_or_critical(&cve.severity) {
            continue;
        }
        for row in inventory {
            if let Some(crit) = first_matching_criteria(row, &cve.configurations) {
                let key = (cve.id.clone(), row.cpe.clone());
                if seen.insert(key) {
                    hits.push(Hit {
                        cve_id: cve.id.clone(),
                        severity: cve.severity.to_ascii_uppercase(),
                        score: cve.score,
                        inventory: row.clone(),
                        matched_criteria: crit,
                        published: cve.published.clone(),
                        description: cve.description.clone(),
                    });
                }
            }
        }
    }
    hits.sort_by(|a, b| {
        severity_rank(&b.severity)
            .cmp(&severity_rank(&a.severity))
            .then_with(|| a.cve_id.cmp(&b.cve_id))
            .then_with(|| a.inventory.cpe.cmp(&b.inventory.cpe))
    });
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inv(part: &str, vendor: &str, product: &str, version: &str) -> InventoryRow {
        InventoryRow {
            cpe: format!("cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:*:*:*"),
            name: product.to_string(),
            owner: String::new(),
            line: 2,
            part: part.to_string(),
            vendor: vendor.to_string(),
            product: product.to_string(),
            version: version.to_string(),
            update: "*".to_string(),
        }
    }

    fn range_match(
        criteria: &str,
        start_inc: Option<&str>,
        start_exc: Option<&str>,
        end_inc: Option<&str>,
        end_exc: Option<&str>,
    ) -> CpeMatch {
        CpeMatch {
            vulnerable: true,
            criteria: criteria.to_string(),
            version_start_including: start_inc.map(str::to_string),
            version_start_excluding: start_exc.map(str::to_string),
            version_end_including: end_inc.map(str::to_string),
            version_end_excluding: end_exc.map(str::to_string),
        }
    }

    #[test]
    fn parse_cpe_23_and_legacy() {
        let a = split_cpe("cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*").unwrap();
        assert_eq!(a[2], "a");
        assert_eq!(a[3], "openssl");
        assert_eq!(a[4], "openssl");
        assert_eq!(a[5], "3.0.13");
        assert_eq!(a.len(), 13);

        let b = split_cpe("cpe:/a:apache:log4j:2.14.1").unwrap();
        assert_eq!(b[2], "a");
        assert_eq!(b[3], "apache");
        assert_eq!(b[4], "log4j");
        assert_eq!(b[5], "2.14.1");
        assert_eq!(b.len(), 13);
    }

    #[test]
    fn version_compare_numeric_not_lexicographic() {
        assert_eq!(version_cmp("1.10", "1.9"), Ordering::Greater);
        assert_eq!(version_cmp("1.2", "1.2.0"), Ordering::Equal);
        assert_eq!(version_cmp("2.15.0", "2.14.1"), Ordering::Greater);
    }

    #[test]
    fn version_ranges_including_excluding() {
        let m = range_match(
            "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
            Some("2.0"),
            None,
            None,
            Some("2.15.0"),
        );
        let row = inv("a", "apache", "log4j", "2.14.1");
        assert!(version_in_range(&row.version, &m));
        assert!(!version_in_range("2.15.0", &m));
        assert!(version_in_range("2.0", &m));
        assert!(!version_in_range("1.9", &m));
        assert!(version_in_range("*", &m));
        assert!(version_in_range("-", &m));
    }

    #[test]
    fn exact_version_when_no_range() {
        let m = range_match(
            "cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*",
            None,
            None,
            None,
            None,
        );
        assert!(version_in_range("3.0.13", &m));
        assert!(!version_in_range("3.0.12", &m));
    }

    #[test]
    fn node_or_and_negate() {
        let log4j = inv("a", "apache", "log4j", "2.14.1");
        let openssl = inv("a", "openssl", "openssl", "3.0.13");
        let m_log = range_match(
            "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*",
            None,
            None,
            None,
            None,
        );
        let m_ssl = range_match(
            "cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*",
            None,
            None,
            None,
            None,
        );

        let or_node = Node {
            operator: Some("OR".into()),
            negate: Some(false),
            cpe_match: vec![m_log.clone(), m_ssl.clone()],
            children: vec![],
        };
        assert!(node_matches(&log4j, &or_node));
        assert!(node_matches(&openssl, &or_node));

        let and_node = Node {
            operator: Some("AND".into()),
            negate: Some(false),
            cpe_match: vec![m_log.clone(), m_ssl.clone()],
            children: vec![],
        };
        assert!(!node_matches(&log4j, &and_node));

        let neg = Node {
            operator: Some("OR".into()),
            negate: Some(true),
            cpe_match: vec![m_log],
            children: vec![],
        };
        assert!(!node_matches(&log4j, &neg));
        assert!(node_matches(&openssl, &neg));
    }

    #[test]
    fn match_all_skips_low_medium() {
        let row = inv("a", "apache", "log4j", "2.14.1");
        let cfg = vec![Configuration {
            operator: None,
            negate: None,
            nodes: vec![Node {
                operator: Some("OR".into()),
                negate: None,
                cpe_match: vec![range_match(
                    "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*",
                    Some("2.0"),
                    None,
                    None,
                    Some("2.15.0"),
                )],
                children: vec![],
            }],
        }];
        let cves = vec![
            StoredCve {
                id: "CVE-MED".into(),
                severity: "MEDIUM".into(),
                score: Some(5.0),
                published: "2021-01-01".into(),
                description: "no".into(),
                configurations: cfg.clone(),
            },
            StoredCve {
                id: "CVE-2021-44228".into(),
                severity: "CRITICAL".into(),
                score: Some(10.0),
                published: "2021-12-10".into(),
                description: "log4j".into(),
                configurations: cfg,
            },
        ];
        let hits = match_all(&[row], &cves);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].cve_id, "CVE-2021-44228");
    }
}

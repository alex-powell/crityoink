use std::fs;
use std::path::Path;

use chrono::Utc;

use crate::cpe::Hit;
use crate::csv_inv::InventoryRow;
use crate::db::StoredDb;
use crate::error::Result;

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn score_str(score: Option<f64>) -> String {
    match score {
        Some(s) => format!("{s:.1}"),
        None => String::new(),
    }
}

pub fn render(hits: &[Hit], inventory: &[InventoryRow], db: &StoredDb) -> String {
    let generated = Utc::now().format("%Y-%m-%d %H:%M UTC").to_string();
    let rows = if hits.is_empty() {
        "<tr><td colspan='9'>No HIGH/CRITICAL matches.</td></tr>".to_string()
    } else {
        hits.iter()
            .map(|h| {
                let nvd = format!("https://nvd.nist.gov/vuln/detail/{}", esc(&h.cve_id));
                format!(
                    "<tr class='{sev}'>\
                <td><a href='{nvd}'>{cve}</a></td>\
                <td>{sev_disp}</td><td>{score}</td>\
                <td>{name}</td><td>{owner}</td>\
                <td><code>{cpe}</code></td>\
                <td><code>{crit}</code></td>\
                <td>{pub}</td>\
                <td>{desc}</td>\
                </tr>",
                    sev = esc(&h.severity.to_ascii_lowercase()),
                    nvd = nvd,
                    cve = esc(&h.cve_id),
                    sev_disp = esc(&h.severity),
                    score = esc(&score_str(h.score)),
                    name = esc(&h.inventory.name),
                    owner = esc(&h.inventory.owner),
                    cpe = esc(&h.inventory.cpe),
                    crit = esc(&h.matched_criteria),
                    pub = esc(&h.published),
                    desc = esc(&h.description),
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };

    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>crityoink report</title>
<style>
body {{ font-family: ui-sans-serif, system-ui, sans-serif; margin: 2rem; color: #111; }}
h1 {{ font-size: 1.4rem; }}
.meta, .note {{ color: #555; margin-bottom: 1.5rem; max-width: 70rem; }}
table {{ border-collapse: collapse; width: 100%; font-size: 0.9rem; }}
th, td {{ border-bottom: 1px solid #ddd; padding: 0.45rem 0.5rem; text-align: left; vertical-align: top; }}
th {{ background: #111; color: #fff; position: sticky; top: 0; }}
tr.critical td:nth-child(2) {{ color: #9b1c1c; font-weight: 700; }}
tr.high td:nth-child(2) {{ color: #b45309; font-weight: 700; }}
code {{ font-size: 0.78rem; word-break: break-all; }}
a {{ color: #1d4ed8; }}
</style>
</head>
<body>
<h1>crityoink local NVD report</h1>
<p class="meta">
Generated {generated}.
NVD sync: {sync}.
Source: {source}.
Stored High: {high}, Critical: {critical}, total: {total}.
Inventory: {inv} CPE(s).
Findings: {findings}.
CHECK made no network calls.
</p>
<p class="note">
This report lists CPE configuration matches against a local High/Critical CVE database.
A match is not a claim that the software is exploited, exploitable in your environment,
or confirmed vulnerable beyond the CPE configuration rules used here.
</p>
<table>
<thead>
<tr>
<th>CVE</th><th>Severity</th><th>Score</th>
<th>Name</th><th>Owner</th><th>Your CPE</th>
<th>Matched NVD CPE</th><th>Published</th><th>Description</th>
</tr>
</thead>
<tbody>
{rows}
</tbody>
</table>
</body>
</html>
"#,
        generated = esc(&generated),
        sync = esc(&db.synced_at),
        source = esc(&db.source),
        high = db.counts.high,
        critical = db.counts.critical,
        total = db.counts.total_stored,
        inv = inventory.len(),
        findings = hits.len(),
        rows = rows,
    )
}

pub fn write(path: &Path, hits: &[Hit], inventory: &[InventoryRow], db: &StoredDb) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(path, render(hits, inventory, db))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csv_inv::InventoryRow;
    use crate::db::{Counts, StoredDb};

    fn row() -> InventoryRow {
        InventoryRow {
            cpe: "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*".into(),
            name: "Log4j 2.14.1".into(),
            owner: "app".into(),
            line: 2,
            part: "a".into(),
            vendor: "apache".into(),
            product: "log4j".into(),
            version: "2.14.1".into(),
            update: "*".into(),
        }
    }

    #[test]
    fn html_contains_expected_bits_and_does_not_claim_exploit() {
        let inv = row();
        let hit = Hit {
            cve_id: "CVE-2021-44228".into(),
            severity: "CRITICAL".into(),
            score: Some(10.0),
            inventory: inv.clone(),
            matched_criteria: "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*".into(),
            published: "2021-12-10".into(),
            description: "JNDI lookup".into(),
        };
        let db = StoredDb {
            schema_version: 1,
            synced_at: "2026-01-01T00:00:00Z".into(),
            source: "https://services.nvd.nist.gov/rest/json/cves/2.0".into(),
            counts: Counts {
                high: 0,
                critical: 1,
                total_stored: 1,
            },
            vulnerabilities: vec![],
        };
        let html = render(&[hit], &[inv], &db);
        assert!(html.contains("CVE-2021-44228"));
        assert!(html.contains("https://nvd.nist.gov/vuln/detail/CVE-2021-44228"));
        assert!(html.contains("CHECK made no network calls"));
        assert!(html.contains("Log4j 2.14.1"));
        assert!(html.contains("app"));
        assert!(html.contains("cpe:2.3:a:apache:log4j:2.14.1"));
        assert!(html.contains("CRITICAL"));
        assert!(html.contains("10.0"));
        assert!(html.contains("JNDI lookup"));
        assert!(html.contains("not a claim that the software is exploited"));
        assert!(!html.contains("confirmed exploited"));
        assert!(!html.contains("actively exploited"));
    }
}

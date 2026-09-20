use std::fs;
use std::path::Path;

use crate::error::{Error, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InventoryRow {
    pub cpe: String,
    pub name: String,
    pub owner: String,
    pub line: usize,
    pub part: String,
    pub vendor: String,
    pub product: String,
    pub version: String,
    pub update: String,
}

fn sniff_delimiter(header: &str) -> u8 {
    let commas = header.matches(',').count();
    let semis = header.matches(';').count();
    let tabs = header.matches('\t').count();
    if tabs > commas && tabs > semis {
        b'\t'
    } else if semis > commas {
        b';'
    } else {
        b','
    }
}

fn lookup<'a>(fields: &'a [String], aliases: &[&str]) -> Option<usize> {
    for alias in aliases {
        if let Some(i) = fields.iter().position(|f| f.eq_ignore_ascii_case(alias)) {
            return Some(i);
        }
    }
    None
}

pub fn parse(path: &Path) -> Result<Vec<InventoryRow>> {
    let mut text = fs::read_to_string(path)?;
    if let Some(stripped) = text.strip_prefix('\u{feff}') {
        text = stripped.to_string();
    }
    let header_line = text.lines().next().unwrap_or("");
    let delim = sniff_delimiter(header_line);
    let mut reader = csv::ReaderBuilder::new()
        .delimiter(delim)
        .flexible(true)
        .from_reader(text.as_bytes());
    let headers = reader
        .headers()
        .map_err(|e| Error::msg(format!("CSV has no header row: {e}")))?
        .clone();
    if headers.is_empty() {
        return Err(Error::msg("CSV has no header row"));
    }
    let fields: Vec<String> = headers.iter().map(|h| h.trim().to_string()).collect();
    let cpe_idx = lookup(&fields, &["cpe", "cpe23", "cpe_uri", "uri"]).ok_or_else(|| {
        Error::msg(format!(
            "CSV needs a column named cpe (or cpe23 / cpe_uri). Got: {}",
            fields.join(", ")
        ))
    })?;
    let name_idx = lookup(&fields, &["name", "component", "id", "product"]);
    let owner_idx = lookup(&fields, &["owner", "team", "vendor"]);

    let mut rows = Vec::new();
    for (i, rec) in reader.records().enumerate() {
        let line = i + 2;
        let rec = rec?;
        let cpe = rec.get(cpe_idx).unwrap_or("").trim().to_string();
        if cpe.is_empty() || cpe.starts_with('#') {
            continue;
        }
        let Some(parts) = crate::cpe::split_cpe(&cpe) else {
            eprintln!("skip line {line}: not a CPE: {cpe}");
            continue;
        };
        let name = name_idx
            .and_then(|idx| rec.get(idx))
            .unwrap_or("")
            .trim()
            .to_string();
        let owner = owner_idx
            .and_then(|idx| rec.get(idx))
            .unwrap_or("")
            .trim()
            .to_string();
        rows.push(InventoryRow {
            cpe,
            name,
            owner,
            line,
            part: parts[2].to_ascii_lowercase(),
            vendor: parts[3].to_ascii_lowercase(),
            product: parts[4].to_ascii_lowercase(),
            version: parts[5].clone(),
            update: parts[6].clone(),
        });
    }
    if rows.is_empty() {
        return Err(Error::msg("No usable CPE rows in CSV"));
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    #[test]
    fn parses_name_owner_cpe_and_aliases() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("inv.csv");
        let mut f = fs::File::create(&path).unwrap();
        writeln!(
            f,
            "component,team,cpe23\nOpenSSL,platform,cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*"
        )
        .unwrap();
        let rows = parse(&path).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "OpenSSL");
        assert_eq!(rows[0].owner, "platform");
        assert_eq!(rows[0].vendor, "openssl");
        assert_eq!(rows[0].version, "3.0.13");
    }

    #[test]
    fn rejects_csv_without_cpe_column() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.csv");
        fs::write(&path, "name,owner\nfoo,bar\n").unwrap();
        let err = parse(&path).unwrap_err();
        assert!(err.to_string().contains("cpe"));
    }
}

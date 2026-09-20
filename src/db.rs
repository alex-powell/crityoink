use std::env;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

pub const DB_FILENAME: &str = "nvd.json";
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Counts {
    pub high: usize,
    pub critical: usize,
    pub total_stored: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredDb {
    pub schema_version: u32,
    pub synced_at: String,
    pub source: String,
    pub counts: Counts,
    pub vulnerabilities: Vec<StoredCve>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCve {
    pub id: String,
    pub severity: String,
    pub score: Option<f64>,
    pub published: String,
    pub description: String,
    #[serde(default)]
    pub configurations: Vec<Configuration>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Configuration {
    #[serde(default)]
    pub operator: Option<String>,
    #[serde(default)]
    pub negate: Option<bool>,
    #[serde(default)]
    pub nodes: Vec<Node>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Node {
    #[serde(default)]
    pub operator: Option<String>,
    #[serde(default)]
    pub negate: Option<bool>,
    #[serde(default, rename = "cpeMatch")]
    pub cpe_match: Vec<CpeMatch>,
    #[serde(default)]
    pub children: Vec<Node>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CpeMatch {
    #[serde(default)]
    pub vulnerable: bool,
    #[serde(default)]
    pub criteria: String,
    #[serde(default, rename = "versionStartIncluding")]
    pub version_start_including: Option<String>,
    #[serde(default, rename = "versionStartExcluding")]
    pub version_start_excluding: Option<String>,
    #[serde(default, rename = "versionEndIncluding")]
    pub version_end_including: Option<String>,
    #[serde(default, rename = "versionEndExcluding")]
    pub version_end_excluding: Option<String>,
}

impl StoredDb {
    pub fn from_cves(source: String, synced_at: String, mut vulns: Vec<StoredCve>) -> Self {
        vulns.sort_by(|a, b| a.id.cmp(&b.id));
        let high = vulns
            .iter()
            .filter(|v| v.severity.eq_ignore_ascii_case("HIGH"))
            .count();
        let critical = vulns
            .iter()
            .filter(|v| v.severity.eq_ignore_ascii_case("CRITICAL"))
            .count();
        let total_stored = vulns.len();
        Self {
            schema_version: SCHEMA_VERSION,
            synced_at,
            source,
            counts: Counts {
                high,
                critical,
                total_stored,
            },
            vulnerabilities: vulns,
        }
    }
}

pub fn default_data_dir() -> PathBuf {
    data_dir_from_env(env::var_os("XDG_CACHE_HOME"), env::var_os("HOME"))
}

pub fn data_dir_from_env(
    xdg_cache: Option<impl AsRef<OsStr>>,
    home: Option<impl AsRef<OsStr>>,
) -> PathBuf {
    if let Some(xdg) = xdg_cache {
        let xdg = PathBuf::from(xdg.as_ref());
        if !xdg.as_os_str().is_empty() {
            return xdg.join("crityoink");
        }
    }
    match home {
        Some(h) => PathBuf::from(h.as_ref()).join(".cache").join("crityoink"),
        None => PathBuf::from(".cache").join("crityoink"),
    }
}

pub fn db_path(data_dir: &Path) -> PathBuf {
    data_dir.join(DB_FILENAME)
}

pub fn load(data_dir: &Path) -> Result<StoredDb> {
    let path = db_path(data_dir);
    if !path.exists() {
        return Err(Error::NoDb(path, data_dir.to_path_buf()));
    }
    let file = File::open(&path)?;
    let db: StoredDb = serde_json::from_reader(BufReader::new(file))?;
    Ok(db)
}

/// Atomically replace `nvd.json` with a complete new database (full refresh).
pub fn save(data_dir: &Path, db: &StoredDb) -> Result<()> {
    fs::create_dir_all(data_dir)?;
    let dest = db_path(data_dir);
    let tmp = data_dir.join("nvd.json.tmp");
    {
        let file = File::create(&tmp)?;
        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, db)?;
        writer.flush().map_err(Error::from)?;
        writer.get_ref().sync_all()?;
    }
    fs::rename(&tmp, &dest)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Read;

    fn sample_cve(id: &str, severity: &str) -> StoredCve {
        StoredCve {
            id: id.to_string(),
            severity: severity.to_string(),
            score: Some(9.8),
            published: "2021-12-10".to_string(),
            description: "test".to_string(),
            configurations: vec![],
        }
    }

    #[test]
    fn default_dir_uses_xdg_then_home() {
        let xdg = data_dir_from_env(Some("/tmp/xdg-cache"), Some("/home/user"));
        assert_eq!(xdg, PathBuf::from("/tmp/xdg-cache/crityoink"));
        let home = data_dir_from_env(None::<&str>, Some("/home/user"));
        assert_eq!(home, PathBuf::from("/home/user/.cache/crityoink"));
    }

    #[test]
    fn wipe_rebuild_replaces_previous_and_writes_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let first = StoredDb::from_cves(
            "https://example.invalid/nvd".into(),
            "2020-01-01T00:00:00Z".into(),
            vec![sample_cve("CVE-2020-0001", "HIGH")],
        );
        save(dir.path(), &first).unwrap();
        let second = StoredDb::from_cves(
            "https://services.nvd.nist.gov/rest/json/cves/2.0".into(),
            "2026-01-02T03:04:05Z".into(),
            vec![
                sample_cve("CVE-2021-44228", "CRITICAL"),
                sample_cve("CVE-2024-0001", "HIGH"),
            ],
        );
        save(dir.path(), &second).unwrap();

        let loaded = load(dir.path()).unwrap();
        assert_eq!(loaded.schema_version, SCHEMA_VERSION);
        assert_eq!(loaded.synced_at, "2026-01-02T03:04:05Z");
        assert_eq!(
            loaded.source,
            "https://services.nvd.nist.gov/rest/json/cves/2.0"
        );
        assert_eq!(loaded.counts.high, 1);
        assert_eq!(loaded.counts.critical, 1);
        assert_eq!(loaded.counts.total_stored, 2);
        assert_eq!(loaded.vulnerabilities.len(), 2);
        assert!(loaded
            .vulnerabilities
            .iter()
            .all(|v| v.id != "CVE-2020-0001"));
        assert!(!dir.path().join("nvd.json.tmp").exists());
    }

    #[test]
    fn load_missing_file_is_error() {
        let dir = tempfile::tempdir().unwrap();
        let err = load(dir.path()).unwrap_err();
        match err {
            Error::NoDb(path, _) => assert_eq!(path, dir.path().join("nvd.json")),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn save_is_valid_json() {
        let dir = tempfile::tempdir().unwrap();
        let db = StoredDb::from_cves(
            "src".into(),
            "now".into(),
            vec![sample_cve("CVE-1", "HIGH")],
        );
        save(dir.path(), &db).unwrap();
        let mut f = File::open(db_path(dir.path())).unwrap();
        let mut buf = String::new();
        f.read_to_string(&mut buf).unwrap();
        assert!(buf.contains("\"total_stored\":1") || buf.contains("\"total_stored\": 1"));
        let _parsed: serde_json::Value = serde_json::from_str(&buf).unwrap();
    }
}

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{Parser, ValueHint};

use crate::error::{Error, Result};
use crate::{cpe, csv_inv, db, html, nvd};

const USAGE: &str = "\
Specify exactly one of --get or --check <csv>.

Usage:
  crityoink --get [--full] [--data-dir DIR]
  crityoink --check CSV [--data-dir DIR] [--out FILE]

--get is incremental lastMod when a watermark exists; --get --full forces a rebuild.
Your CPE inventory is never sent to NVD. --check uses the local database only.";

#[derive(Parser, Debug)]
#[command(
    name = "crityoink",
    version,
    about = "Local High/Critical NVD mirror and offline CPE inventory checker.",
    long_about = "crityoink mirrors High and Critical CVEs from the NVD REST API into a local JSON database, then matches a local CPE inventory CSV without any network access.\n\nThe inventory CSV is never sent to NVD.\nA CPE match is not a claim that a CVE is exploited."
)]
pub struct Cli {
    /// Update the local JSON database from NVD (incremental lastMod delta, or full rebuild)
    #[arg(long)]
    pub get: bool,

    /// With --get, force a full High/Critical rebuild instead of an incremental lastMod delta
    #[arg(long, requires = "get")]
    pub full: bool,

    /// Match inventory CPEs against the local JSON database only and write an HTML report
    #[arg(long, value_name = "CSV", value_hint = ValueHint::FilePath)]
    pub check: Option<PathBuf>,

    /// Directory for the local JSON database (default: ~/.cache/crityoink)
    #[arg(long, value_name = "DIR", value_hint = ValueHint::DirPath)]
    pub data_dir: Option<PathBuf>,

    /// HTML report output path (check only; default: crityoink-report.html)
    #[arg(long, value_name = "FILE", value_hint = ValueHint::FilePath)]
    pub out: Option<PathBuf>,
}

pub fn run<I, T>(args: I) -> i32
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    match try_run(args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("{e}");
            1
        }
    }
}

fn try_run<I, T>(args: I) -> Result<i32>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let cli = match Cli::try_parse_from(args) {
        Ok(c) => c,
        Err(e) => {
            let _ = e.print();
            return Ok(if e.exit_code() == 0 { 0 } else { 1 });
        }
    };

    match (cli.get, cli.check.as_ref()) {
        (true, None) => cmd_get(cli.data_dir.as_ref(), cli.full),
        (false, Some(csv)) => cmd_check(csv, cli.data_dir.as_ref(), cli.out.as_ref()),
        (true, Some(_)) | (false, None) => {
            eprintln!("{USAGE}");
            Ok(1)
        }
    }
}

fn resolve_data_dir(explicit: Option<&PathBuf>) -> PathBuf {
    explicit.cloned().unwrap_or_else(db::default_data_dir)
}

fn cmd_get(data_dir: Option<&PathBuf>, force_full: bool) -> Result<i32> {
    let data_dir = resolve_data_dir(data_dir);
    eprintln!("Updating local NVD database in {}.", data_dir.display());
    eprintln!(
        "Calling {} without an API key; sleeping ~{}ms between requests. This can take a long time.",
        nvd::NVD_BASE,
        nvd::DEFAULT_MIN_INTERVAL.as_millis()
    );
    std::fs::create_dir_all(&data_dir)?;
    let existing = match db::load(&data_dir) {
        Ok(db) => Some(db),
        Err(Error::NoDb(_, _)) => None,
        Err(e) => {
            eprintln!("Local database unreadable ({e}); falling back to full rebuild.");
            None
        }
    };
    let db = nvd::refresh_from_nvd(
        &nvd::UreqClient,
        &nvd::StdSleeper,
        nvd::DEFAULT_MIN_INTERVAL,
        existing,
        force_full,
    )?;
    db::save(&data_dir, &db)?;
    eprintln!(
        "Stored {} CVE(s) ({} high, {} critical) at {}.",
        db.counts.total_stored,
        db.counts.high,
        db.counts.critical,
        db::db_path(&data_dir).display()
    );
    eprintln!("CHECK uses only this directory and makes no network calls.");
    Ok(0)
}

fn cmd_check(csv_path: &PathBuf, data_dir: Option<&PathBuf>, out: Option<&PathBuf>) -> Result<i32> {
    // Offline only: load the local JSON DB and never call NVD.
    let data_dir = resolve_data_dir(data_dir);
    let db = db::load(&data_dir)?;
    let inventory = csv_inv::parse(csv_path)?;
    let hits = cpe::match_all(&inventory, &db.vulnerabilities);
    let out = out
        .cloned()
        .unwrap_or_else(|| PathBuf::from("crityoink-report.html"));
    html::write(&out, &hits, &inventory, &db)?;
    eprintln!("{} finding(s) → {}", hits.len(), out.display());
    Ok(if hits.is_empty() { 0 } else { 2 })
}

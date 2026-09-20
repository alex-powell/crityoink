use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_crityoink"))
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

fn example_csv() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/products.example.csv")
}

fn data_dir_with_fixture(tmp: &Path) -> PathBuf {
    let dir = tmp.join("cache");
    fs::create_dir_all(&dir).unwrap();
    fs::copy(fixture("nvd-small.json"), dir.join("nvd.json")).unwrap();
    dir
}

fn run_ok(mut cmd: Command) -> (i32, String, String) {
    let out = cmd.output().expect("run crityoink");
    let code = out.status.code().unwrap_or(255);
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (code, stdout, stderr)
}

#[test]
fn help_exits_zero() {
    let (code, stdout, stderr) = run_ok({
        let mut c = bin();
        c.arg("--help");
        c
    });
    assert_eq!(code, 0, "stderr={stderr}");
    assert!(stdout.contains("--get"));
    assert!(stdout.contains("--check"));
    assert!(stdout.contains("--data-dir"));
    assert!(stdout.contains("--full"));
    let help = format!("{stdout}{stderr}").to_ascii_lowercase();
    assert!(
        help.contains("incremental") && help.contains("full"),
        "help should describe incremental vs full, got {stdout}"
    );
}

#[test]
fn neither_flag_exits_one() {
    let (code, _stdout, stderr) = run_ok(bin());
    assert_eq!(code, 1);
    assert!(
        stderr.contains("--get") && stderr.contains("--check"),
        "stderr={stderr}"
    );
}

#[test]
fn both_flags_exit_one() {
    let (code, _stdout, stderr) = run_ok({
        let mut c = bin();
        c.args(["--get", "--check", "x.csv"]);
        c
    });
    assert_eq!(code, 1);
    assert!(
        stderr.contains("exactly one") || stderr.contains("--get"),
        "stderr={stderr}"
    );
}

#[test]
fn check_with_fixture_finds_and_exits_two() {
    let tmp = tempfile::tempdir().unwrap();
    let data = data_dir_with_fixture(tmp.path());
    let report = tmp.path().join("report.html");
    let (code, _stdout, stderr) = run_ok({
        let mut c = bin();
        c.args([
            "--check",
            example_csv().to_str().unwrap(),
            "--data-dir",
            data.to_str().unwrap(),
            "--out",
            report.to_str().unwrap(),
        ]);
        c
    });
    assert_eq!(code, 2, "stderr={stderr}");
    assert!(stderr.contains("finding"), "stderr={stderr}");
    let html = fs::read_to_string(&report).unwrap();
    assert!(html.contains("CVE-2021-44228"));
    assert!(html.contains("CVE-2024-TEST-OPENSSL"));
    assert!(html.contains("https://nvd.nist.gov/vuln/detail/CVE-2021-44228"));
    assert!(html.contains("CHECK made no network calls"));
    assert!(!html.contains("CVE-2020-MEDIUM"));
    assert!(html.contains("not a claim that the software is exploited"));
}

#[test]
fn check_with_no_findings_exits_zero() {
    let tmp = tempfile::tempdir().unwrap();
    let data = data_dir_with_fixture(tmp.path());
    let report = tmp.path().join("report.html");
    let (code, _stdout, stderr) = run_ok({
        let mut c = bin();
        c.args([
            "--check",
            fixture("inventory-miss.csv").to_str().unwrap(),
            "--data-dir",
            data.to_str().unwrap(),
            "--out",
            report.to_str().unwrap(),
        ]);
        c
    });
    assert_eq!(code, 0, "stderr={stderr}");
    let html = fs::read_to_string(&report).unwrap();
    assert!(html.contains("No HIGH/CRITICAL matches"));
    assert!(html.contains("CHECK made no network calls"));
}

#[test]
fn check_missing_db_exits_one() {
    let tmp = tempfile::tempdir().unwrap();
    let empty = tmp.path().join("empty");
    fs::create_dir_all(&empty).unwrap();
    let (code, _stdout, stderr) = run_ok({
        let mut c = bin();
        c.args([
            "--check",
            example_csv().to_str().unwrap(),
            "--data-dir",
            empty.to_str().unwrap(),
        ]);
        c
    });
    assert_eq!(code, 1, "stderr={stderr}");
    assert!(
        stderr.contains("No local NVD database") || stderr.contains("nvd.json"),
        "stderr={stderr}"
    );
}

#[test]
fn check_does_not_require_network() {
    let tmp = tempfile::tempdir().unwrap();
    let data = data_dir_with_fixture(tmp.path());
    let report = tmp.path().join("offline.html");
    let (code, _stdout, stderr) = run_ok({
        let mut c = bin();
        c.env("https_proxy", "http://127.0.0.1:1")
            .env("HTTPS_PROXY", "http://127.0.0.1:1")
            .env("http_proxy", "http://127.0.0.1:1")
            .env("HTTP_PROXY", "http://127.0.0.1:1")
            .env("ALL_PROXY", "http://127.0.0.1:1")
            .args([
                "--check",
                example_csv().to_str().unwrap(),
                "--data-dir",
                data.to_str().unwrap(),
                "--out",
                report.to_str().unwrap(),
            ]);
        c
    });
    assert_eq!(code, 2, "offline check failed: {stderr}");
}

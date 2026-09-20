# crityoink

Local High/Critical NVD mirror and offline CPE inventory checker.

`--get` talks to the [NVD REST API](https://services.nvd.nist.gov/rest/json/cves/2.0) **without an API key** and fully rebuilds a local JSON database of High and Critical CVEs. `--check` matches a CPE inventory CSV against that database only. **The inventory never leaves the machine.** `--check` makes no network calls.

A CPE match is a configuration hit, not a claim that a CVE is exploited or exploitable in your environment.

## Install

Requires [Rust and cargo](https://rustup.rs).

```sh
cargo install --git https://github.com/alex-powell/crityoink
```

Or from a clone:

```sh
./install.sh
```

`install.sh` runs the same `cargo install --git …` command, or copies a `crityoink` binary if one is present next to the script. Put `~/.cargo/bin` (or `~/.local/bin` when copying a binary) on your `PATH`.

Build from a checkout:

```sh
cargo build --release
./target/release/crityoink --help
```

## Usage

```sh
crityoink --get
crityoink --check example.csv
```

Specify exactly one of `--get` or `--check <csv>`. Optional flags:

```
crityoink --get --data-dir ~/.cache/crityoink

crityoink --check products.csv --data-dir ~/.cache/crityoink --out report.html
```

`--get` wipes and rebuilds the entire local JSON database (not incremental). It queries High and Critical severities, skips Rejected CVEs, and sleeps about 7.5 seconds between requests to stay under the no-key NVD budget (typically 5 requests per 30 seconds) with padding. HTTP 403/429 and `Retry-After` are respected.

`--check` reads only the local database. It will not contact NVD.

### Inventory CSV

A header row is required. Column `cpe` is mandatory (`cpe23` / `cpe_uri` / `uri` also work). Optional: `name`, `owner` (or `component` / `id` / `product` and `team` / `vendor`).

```csv
name,owner,cpe
OpenSSL 3.0.13,platform,cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*
```

Legacy `cpe:/a:vendor:product:version` also works. See `examples/products.example.csv`.

## Data directory

Default: **`~/.cache/crityoink/`** (or `$XDG_CACHE_HOME/crityoink` if `XDG_CACHE_HOME` is set).

The database file is `nvd.json` in that directory. Override with `--data-dir`.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | Success (`--get`) or `--check` with no findings |
| 2 | `--check` produced one or more findings |
| 1 | Error (bad usage, missing DB, I/O, HTTP failure, …) |

## Air-gap workflow

1. Connected box: `crityoink --get --data-dir ./nvd-db`
2. Copy `./nvd-db` (the directory containing `nvd.json`) to the isolated machine
3. Isolated box: `crityoink --check products.csv --data-dir ./nvd-db --out report.html`

`--check` never needs the network. The CSV is not uploaded anywhere.

## Limits

- Only High and Critical CVEs are stored. Low and Medium are dropped.
- Rejected CVE status (`vulnStatus` Rejected / Rejected-related) is ignored and not stored.
- `--get` is a full refresh every time. A complete High+Critical sync is slow because of NVD no-key rate limits (sleep ~7.5s per request, plus backoff on 403/429). That is expected.
- Version comparison is a dotted-numeric / alpha-token heuristic, not every vendor scheme.
- Matching uses vulnerable `cpeMatch` entries and configuration node AND/OR/negate. Wildcards other than `*` on vendor/product are not supported.
- Matching is per inventory CPE. A report row is a configuration match, not proof of exploitability.

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Pull requests are welcome; the maintainer reviews and merges.

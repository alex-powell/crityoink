# crityoink

Local High/Critical NVD mirror and offline CPE inventory checker.

`--get` talks to the [NVD REST API](https://services.nvd.nist.gov/rest/json/cves/2.0) **without an API key** and updates a local JSON database of High and Critical CVEs (incremental lastMod delta when a watermark exists; full rebuild otherwise). `--check` matches a CPE inventory CSV against that database only. **The inventory never leaves the machine.** `--check` makes no network calls.

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
crityoink --get --full
crityoink --check example.csv
```

Specify exactly one of `--get` or `--check <csv>`. Optional flags:

```
crityoink --get --data-dir ~/.cache/crityoink
crityoink --get --full --data-dir ~/.cache/crityoink

crityoink --check products.csv --data-dir ~/.cache/crityoink --out report.html
```

`--get` with a valid local database and last-mod watermark fetches NVD CVEs modified since that watermark (`lastModStartDate` / `lastModEndDate`) and **merges** them: High/Critical non-Rejected records are inserted or replaced (including upgrades from below High/Critical), and CVEs that became Rejected or dropped below High/Critical are removed. Unrelated local entries are left alone. `--get --full` forces a full High/Critical rebuild even when a watermark exists. First run, a missing or unreadable database, an old schema, a missing watermark, or a watermark older than NVD's lastMod window (typically 120 days) also fall back to a full rebuild.

Full rebuild queries High and Critical severities and skips Rejected CVEs. Incremental lastMod queries are unfiltered by severity and include Rejected records so demotions can be applied. Requests sleep about 7.5 seconds to stay under the no-key NVD budget (typically 5 requests per 30 seconds) with padding. HTTP 403/429 and `Retry-After` are respected.

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

The database file is `nvd.json` in that directory. Override with `--data-dir`. Metadata includes `synced_at` and a `last_mod_end` watermark used for incremental `--get`.

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

`--check` never needs the network. The CSV is not uploaded anywhere. Copy the whole data directory (including `nvd.json` with its last-mod watermark) so the isolated machine can `--check` and a later connected `--get` can stay incremental.

## Limits

- Only High and Critical CVEs are stored. Low and Medium are dropped.
- Rejected CVE status (`vulnStatus` Rejected / Rejected-related) is ignored and not stored.
- `--get --full` (and the first run, or a watermark older than ~120 days) is a complete High+Critical sync. That is slow because of NVD no-key rate limits (sleep ~7.5s per request, plus backoff on 403/429). Incremental `--get` is much smaller after the first successful sync.
- Version comparison is a dotted-numeric / alpha-token heuristic, not every vendor scheme.
- Matching uses vulnerable `cpeMatch` entries and configuration node AND/OR/negate. Wildcards other than `*` on vendor/product are not supported.
- Matching is per inventory CPE. A report row is a configuration match, not proof of exploitability.

## License

Apache License 2.0. See [LICENSE](LICENSE).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Pull requests are welcome; the maintainer reviews and merges.

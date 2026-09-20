# Contributing to crityoink

Pull requests are welcome.

The maintainer reviews and merges changes. There is no promise of automatic merge.

## Guidelines

- Keep changes scoped to the problem at hand.
- Do not send a CPE inventory to NVD, and do not add API-key requirements.
- `--check` must stay offline (local JSON database only).
- Store High and Critical CVEs only; skip Rejected (`vulnStatus` Rejected / Rejected-related).
- `--get` updates the local database via a lastMod delta (upsert High/Critical, including upgrades; remove Rejected or demoted). `--get --full` forces a full rebuild.
- Do not claim that a CPE match means a CVE is exploited.

## Before opening a PR

```sh
cargo test
cargo build --release
```

Both should pass.

## License

Contributions are accepted under the Apache License 2.0 (see `LICENSE`).

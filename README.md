# lookingglass-v2

Confusion / traffic-obfuscation research (Rust + WASM). Companion research repository
to [FIBEMATE](https://github.com/Lennonhaha/fibemate) and
[lookingglass](https://github.com/Lennonhaha/lookingglass).

> ⚠️ **Research code — NOT production.** Exploratory Rust + WASM implementation of
> layered混淆 (traffic obfuscation) techniques. No security guarantees; parameters
> are illustrative.

## Layout

- `src/` — Rust implementation (see `Cargo.toml`, crate `lgv2`).
- `pkg/` — WASM build artifacts / bindings.
- `Cargo.toml` declares the crate; **license field intentionally added via repo
  LICENSE (GPL-3.0-only)** — see below.

## License

GPL-3.0-only. See [LICENSE](./LICENSE).

## Related

- `lookingglass` — LWE trapdoor research (Node.js).
- `fibemate` — the PQC engineering-validation platform these studies inform.

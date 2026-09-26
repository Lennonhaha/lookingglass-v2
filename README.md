# LookingGlass v2 — LWE-based Confusion Engine

**Version 2.2.2** → v2.4 (WIP)

A pure-Rust confusion engine for obfuscating data at the byte level,
using AES S-box substitution, Fisher-Yates permutation, and XOR
keystream layers — with variable depth and session binding.

## Architecture

```
src/
├── lib.rs              Core 7-layer confusion engine (WASM-compatible)
│                       lgv2_confuse / lgv2_deconfuse (base)
│                       lgv2_confuse_ex / lgv2_deconfuse_ex (session-bound)
│                       lgv2_confuse_full (confuse + KEM binding)
├── control_flow.rs     Opaque predicates + constant-time executor
├── crypto_binding.rs   Keccak-256 + ML-KEM shared secret binding
├── dynamic_path.rs     Dynamic path selector (deprecated, kept for reference)
└── secure_cleanup.rs   RAII secure buffer with runtime zeroization
```

## Build

```sh
cargo build              # native library
cargo build --release    # release (LTO + codegen-units=1)
cargo test               # 33 tests, 0 warnings
```

## WASM

```sh
wasm-pack build --target web
```

Output: `pkg/lgv2_bg.wasm` + `pkg/lgv2.js`

## API Overview

| Function | Purpose |
|---|---|
| `lgv2_confuse(data, seed)` | 7-layer confusion |
| `lgv2_deconfuse(data, seed)` | Inverse |
| `lgv2_confuse_d(data, seed, depth)` | Variable depth (1–7) |
| `lgv2_confuse_ex(data, seed, session_key, depth)` | Session-differentiated |
| `lgv2_confuse_full(data, seed, session_key, kem_ss, depth)` | Full: confuse + KEM bind |
| `lgv2_bind_kem(data, kem_ss)` | Keccak-based KEM binding |
| `lgv2_version()` | Version string |

## Security Claims

- **No new cryptographic assumptions.** All operations are standard
  (AES S-box, xorshift64, Fisher-Yates, Keccak-256).
- **Session differentiation** ensures different sessions produce
  different outputs even with the same seed.
- **KEM binding** ties output to an ML-KEM shared secret
  (Keccak-256-derived binding key, XOR stream).
- **Constant-time** layer for alleviating timing side-channels.
- **Secure zeroization** via `SecureBuffer` RAII wrapper.

## License

GPL-3.0-only © 2026 Liu Tianhe (Lennonhaha)
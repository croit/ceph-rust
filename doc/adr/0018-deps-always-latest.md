# 0018 Dependencies: always latest
Status: accepted
Date: 2026-10-09
Decision: all crates use latest released versions (incl. major bumps). Adding a dep: `cargo add <crate>` (picks latest) or check `cargo search`. Periodically + before each milestone: `scripts/deps-latest.sh` (cargo-edit `cargo upgrade --incompatible`, `cargo update`, full check). Breakage from upgrades is fixed, not pinned around. Rust toolchain: latest stable, pinned to an exact version in `rust-toolchain.toml` (currently 1.99.0) and bumped deliberately. License of every dep must stay permissive (0003).

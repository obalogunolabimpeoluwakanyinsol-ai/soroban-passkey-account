# Contributing to soroban-passkey-account

Thank you for your interest in contributing. This is a security-sensitive contract — please read this guide before submitting changes.

## Before you start

- Check existing issues for the work item you want to tackle. If none exists, open one first to discuss the approach before writing code.
- For security vulnerabilities, do **not** open a public issue. See [SECURITY.md](SECURITY.md).

## Development setup

```bash
rustup target add wasm32-unknown-unknown
cargo build --target wasm32-unknown-unknown --release
cargo test
cargo fmt
cargo clippy -- -D warnings
```

All four commands must pass before submitting a PR.

## What we accept

- Bug fixes with a test that reproduces the bug
- Security improvements (discuss in an issue first)
- Performance improvements with benchmarks
- Documentation improvements

## What is out of scope for v1

See the open GitHub issues for planned v2 features. Do not implement social recovery, session keys, or spending limits as part of this contract — those are tracked as separate future projects.

## Pull request process

1. Fork the repo and create a branch off `main`.
2. Write tests for your change. New security-relevant paths require tests.
3. Run `cargo fmt`, `cargo clippy`, and `cargo test` — all must be clean.
4. Open a PR with a clear description of what changed and why.
5. A maintainer will review. Security-relevant changes require two approvals.

## Code style

- Follow standard Rust formatting (`cargo fmt`).
- No `unsafe` code.
- No hand-rolled cryptography. Use Soroban host functions.
- All `unwrap()` calls must either be in tests or have a comment explaining why panic is correct.
- Public functions must have doc comments.

## License

By contributing, you agree your contributions are licensed under MIT.

# Cyber-Rust

Cyber-Rust is a standalone Rust project for safe, read-only cyber and hardware
security workflows. It intentionally does not access kernels, write firmware,
transmit radio signals, or connect to probes.

## Modes

- `easy`: simple secret-marker scans with common directories excluded.
- `advanced`: explicit path inspection and hardware-policy simulation.
- `no-kernel`: confirms the user-space-only operation policy.

## Commands

```powershell
cd cyber-rust
cargo run -- easy scan .
cargo run -- advanced inspect Cargo.toml
cargo run -- advanced hardware-sim
cargo run -- no-kernel
cargo test
```

Hardware operations are simulations only. Real devices require an externally
reviewed driver with authorization, device allowlisting, and independent safety
interlocks.

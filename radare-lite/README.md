# radare-lite

A small, dependency-free, read-only binary-analysis CLI added as a new project in this repository. It is an initial foundation for growing the repo into a professional reverse-engineering toolkit; it does not replace or remove the existing OOP, Cyber-Rust, lexer, or Mojo work.

## Current capabilities

- Identify ELF, PE/DOS, and Mach-O files from their headers and report basic architecture, type, and entry-point metadata where available.
- Extract printable ASCII strings with file offsets.
- Display a bounded hexadecimal view with offsets and ASCII preview.
- Search a file for literal text and print matching offsets.
- Inspect data only: input files are never executed or modified. Files larger than 128 MiB are rejected for now.

## Usage

```text
cargo run --manifest-path radare-lite/Cargo.toml -- info ./sample
cargo run --manifest-path radare-lite/Cargo.toml -- strings ./sample 6
cargo run --manifest-path radare-lite/Cargo.toml -- hexdump ./sample 0 128
cargo run --manifest-path radare-lite/Cargo.toml -- search ./sample "example"
cargo test --manifest-path radare-lite/Cargo.toml
```

This is an early, deliberately bounded step, not a feature-complete replacement for radare2. The next safe milestones are format-specific section and symbol parsing, richer string encodings, a scripting interface, and a tested disassembly layer. Keep analysis authorized and confined to files you own or have permission to inspect.

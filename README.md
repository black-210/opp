# OOP

OOP is an experimental Rust project containing preliminary nRF52840 debug-probe
and software-defined radio (SDR) code. It is not currently a working command-line
tool, fuzzer, firmware scanner, or complete radio application.

## What runs today

The program's `main()` calls `limon_hack_original()` directly. That function
tries to attach to an nRF52840, access core 0, and print its status. If the
connection, core access, or status read fails, it prints an error and returns.
After a successful status read, it also returns immediately. The code below
that return is unreachable.

The program does not currently call the interactive `cli()` function. Running
it does not prompt for commands or start SDR operations.

## Source features

The following routines exist in `src/main.rs`, but they are not connected to
the current entry point:

| Routine | Intended behavior | Current status |
| --- | --- | --- |
| `cli()` | Reads one line and dispatches command text. | Not called by `main()`. Its wildcard match arm comes before the `tx` and `rx` arms, making those later arms unreachable even if `cli()` is called. |
| `limon_hack()` | Attaches to an nRF52840 and reads core 0 status. | Defined but not called by `main()`. |
| `lain_hack_ain_bin_rf()` | Receives SDR samples and computes basic power and FFT-based signal measurements, then prints heuristic messages. | Defined but not reachable through the current program flow. Requires a compatible SoapySDR setup and receiver. |
| `sdr_match()` | Parses a frequency and expression, generates complex samples, and sends them through an SDR transmit stream. | Defined but not reachable through the current program flow. It can transmit RF when connected and invoked; do not use it except with authorized equipment, within applicable regulations, and in a controlled environment. |
| `limon_hack_original()` | Attempts an nRF52840 debug-probe connection and reads core status. | Called by `main()`. It returns after the status check, so the remaining code in the function is not executed. |

The CLI also contains `start`, `stop`, `launch`, and `main` branches, but they
are not usable through the current entry point. The `start` and `stop` branches
only print messages; they do not control a fuzzer or background process.

Although `libafl` is listed as a dependency, the current source does not set up
a fuzzing target, executor, corpus, mutator, or fuzzing loop. Likewise, the
source does not currently read firmware memory or scan a device for secrets.
The `SECRET_KEY` check is in the unreachable portion of
`limon_hack_original()` and examines only a locally generated string.

## Requirements and build notes

- Rust toolchain with edition 2024 support.
- SoapySDR installed and discoverable by the `soapysdr` crate to build the SDR
  dependency.
- A compatible debug probe and nRF52840 to exercise the active `main()` path.
- Compatible SDR hardware and drivers are needed only if the dormant SDR
  routines are later connected and used.

The current source references `meval` in `sdr_match()`, but `meval` is not
listed in `Cargo.toml`. A build may therefore fail at compilation after native
dependencies are available. The project has not yet been validated as a
working application.

## Build and run

```powershell
cargo check
cargo run
```

`cargo run` attempts the nRF52840 connection immediately; it does not start an
interactive menu. Without the expected probe and target, the routine reports a
connection error and exits.

## Limitations

- The interactive CLI and SDR routines are not wired into the entry point.
- The `tx` and `rx` command arms follow a catch-all match arm and are unreachable.
- The SDR receive analysis is preliminary and does not provide a validated
  classification or monitoring result.
- The transmit routine is experimental and has no safeguards for frequency,
  power, or regulatory compliance.
- No fuzzing campaign, firmware-memory scan, or device secret scan is
  implemented.

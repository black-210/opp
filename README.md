# OOP

OOP is a small Rust command-line experiment that combines a placeholder LibAFL
setup with `probe-rs` calls for an nRF52840 development board. It is not a
complete fuzzer, firmware analyzer, or secret scanner.

## What it does

When started, the program reads one line from standard input and handles one of
these commands:

| Command | Immediate response |
| --- | --- |
| `start` | Prints messages saying the fuzzer started. It does not start a fuzzing loop. |
| `stop` | Prints a stopping message. There is no running process to stop. |
| `launch` | Prints a launch message, initializes the placeholder LibAFL object, and calls the board-related routine. |
| `main` | Prints a message and initializes the placeholder LibAFL object. |
| Anything else | Prints `Unknown command`. |

After handling that command, `main` unconditionally initializes the LibAFL
object and calls the board-related routine. As a result, `main_paylode()` runs
twice for `main` and `launch`; the board routine also runs a second time for
`launch`. The `start`, `stop`, and unknown-command paths still reach these
unconditional calls.

### LibAFL placeholder

`main_paylode()` creates a `StdFuzzer` using the numbers `0x9000` and `0x900`,
enables shared objectives, and accesses the objective fields. It does not
configure a target, executor, corpus, mutator, or fuzzing loop, so it does not
perform fuzzing.

### nRF52840 / debug-probe routine

`limon_hack()`:

1. Converts a fixed four-byte array to a vector.
2. Checks for an attached debug probe. If none is found, it prints a message
   and returns.
3. Attempts to auto-attach to an nRF52840 and check core 0.
4. Builds a string from a hard-coded UTF-16 array and checks it for the literal
   `SECRET_KEY`.
5. Attempts another probe attach and obtains core 0.
6. Prepares register values and checks whether the hard-coded UTF-16 array is
   sorted. The provided array is not sorted, so the inner block containing the
   `write_mem_64bit` call is not reached with the current data.

The `SECRET_KEY` check only examines the generated local string; the code does
not read firmware memory or search a device for secrets. The fixed UTF-16 data
does not contain `SECRET_KEY`, so that condition is false. Several pointer,
conversion, and register calculations have no observable effect.

The routine may still fail when a probe is present but the nRF52840 cannot be
attached: it uses `expect` for some connection results. Only run it with
hardware you own or are authorized to debug.

## Requirements

- Rust toolchain supporting edition 2024
- A compatible debug probe and nRF52840 only if exercising the hardware path

The manifest also lists `dudect-bencher`, `ndarray`, and `subtle`; the current
`src/main.rs` does not use them.

## Build and run

```powershell
cargo build
cargo run
```

The program accepts one command on standard input. For example:

```powershell
"launch" | cargo run
```

Without a debug probe, the hardware routine reports that it is skipping the
nRF52840 operations. With a probe, attachment may fail if the target or probe
is unavailable or incompatible.

## Current limitations

- The start/stop messages do not control a background fuzzer.
- No fuzzing campaign or target is configured.
- The secret check uses a fixed local string, not device memory.
- Most calculated values are unused.
- The CLI command does not prevent the unconditional calls at the end of
  `main()`.

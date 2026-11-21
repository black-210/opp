use std::{
    env,
    fs,
    path::Path,
    process,
};

const MAX_FILE_SIZE: u64 = 128 * 1024 * 1024;
const DEFAULT_STRING_MIN: usize = 4;

fn usage() {
    eprintln!(
        "radare-lite — read-only binary triage\n\
         Usage:\n\
         \  radare-lite info <file>\n\
         \  radare-lite strings <file> [min-length]\n\
         \  radare-lite hexdump <file> [offset] [length]\n\
         \  radare-lite search <file> <text>\n\n\
         Files are inspected as data only; they are never executed or modified."
    );
}

fn read_file(path: &Path) -> Result<Vec<u8>, String> {
    let metadata = fs::metadata(path)
        .map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;
    if !metadata.is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    if metadata.len() > MAX_FILE_SIZE {
        return Err(format!(
            "file is {} bytes; the current analysis limit is {} bytes",
            metadata.len(), MAX_FILE_SIZE
        ));
    }
    fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))
}

fn u16_at(bytes: &[u8], offset: usize, little_endian: bool) -> Option<u16> {
    let data: [u8; 2] = bytes.get(offset..offset.checked_add(2)?)?.try_into().ok()?;
    Some(if little_endian { u16::from_le_bytes(data) } else { u16::from_be_bytes(data) })
}

fn u32_at(bytes: &[u8], offset: usize, little_endian: bool) -> Option<u32> {
    let data: [u8; 4] = bytes.get(offset..offset.checked_add(4)?)?.try_into().ok()?;
    Some(if little_endian { u32::from_le_bytes(data) } else { u32::from_be_bytes(data) })
}

fn format_name(bytes: &[u8]) -> &'static str {
    if bytes.starts_with(b"\x7fELF") {
        "ELF"
    } else if bytes.starts_with(b"MZ") {
        "PE/DOS candidate"
    } else if bytes.get(..4).is_some_and(|magic| {
        matches!(magic, [0xfe, 0xed, 0xfa, 0xce] | [0xce, 0xfa, 0xed, 0xfe]
            | [0xfe, 0xed, 0xfa, 0xcf] | [0xcf, 0xfa, 0xed, 0xfe])
    }) {
        "Mach-O"
    } else {
        "unknown/raw data"
    }
}

fn machine_name(machine: u16) -> &'static str {
    match machine {
        0x014c => "x86",
        0x8664 => "x86-64",
        0x01c0 | 0x01c4 => "ARM",
        0xaa64 => "ARM64",
        0x5032 => "RISC-V 32",
        0x5064 => "RISC-V 64",
        _ => "unknown",
    }
}

fn inspect(bytes: &[u8]) -> Vec<String> {
    let mut details = vec![format!("Format: {}", format_name(bytes))];

    if bytes.starts_with(b"\x7fELF") && bytes.len() >= 20 {
        let class = match bytes[4] { 1 => "32-bit", 2 => "64-bit", _ => "unknown class" };
        let endian = match bytes[5] { 1 => true, 2 => false, _ => return details };
        let kind = u16_at(bytes, 16, endian).map(|value| match value {
            1 => "relocatable", 2 => "executable", 3 => "shared object", 4 => "core", _ => "unknown",
        }).unwrap_or("unavailable");
        let machine = u16_at(bytes, 18, endian).map(machine_name).unwrap_or("unknown");
        details.push(format!("Class: {class}"));
        details.push(format!("Byte order: {}", if endian { "little-endian" } else { "big-endian" }));
        details.push(format!("Type: {kind}"));
        details.push(format!("Machine: {machine}"));
        let entry_offset = if class == "32-bit" { 24 } else { 24 };
        let entry = if class == "32-bit" {
            u32_at(bytes, entry_offset, endian).map(u64::from)
        } else {
            bytes.get(entry_offset..entry_offset + 8)
                .and_then(|slice| <[u8; 8]>::try_from(slice).ok())
                .map(|value| if endian { u64::from_le_bytes(value) } else { u64::from_be_bytes(value) })
        };
        if let Some(entry) = entry {
            details.push(format!("Entry point: 0x{entry:x}"));
        }
    } else if bytes.starts_with(b"MZ") {
        if let Some(pe_offset) = u32_at(bytes, 0x3c, true).map(|value| value as usize) {
            if bytes.get(pe_offset..pe_offset.saturating_add(4)) == Some(b"PE\0\0") {
                let machine = u16_at(bytes, pe_offset + 4, true).map(machine_name).unwrap_or("unknown");
                let optional = pe_offset.saturating_add(24);
                details[0] = "Format: PE".to_string();
                details.push(format!("Machine: {machine}"));
                if let Some(entry) = u32_at(bytes, optional + 16, true) {
                    details.push(format!("Entry point RVA: 0x{entry:x}"));
                }
            } else {
                details.push("PE signature: not found at DOS header offset".to_string());
            }
        } else {
            details.push("DOS header: truncated".to_string());
        }
    } else if format_name(bytes) == "Mach-O" && bytes.len() >= 8 {
        let little = matches!(bytes.get(..4), Some([0xce, 0xfa, 0xed, 0xfe] | [0xcf, 0xfa, 0xed, 0xfe]));
        if let Some(cpu) = u32_at(bytes, 4, little) {
            let arch = match cpu & 0x00ff_ffff {
                7 => "x86",
                12 => "ARM",
                _ => "unknown",
            };
            let bits = if cpu & 0x0100_0000 != 0 { "64-bit" } else { "32-bit" };
            details.push(format!("Architecture: {arch} ({bits})"));
        }
    }

    details
}

fn printable_strings(bytes: &[u8], min_length: usize) -> Vec<(usize, String)> {
    if min_length == 0 {
        return Vec::new();
    }
    let mut result = Vec::new();
    let mut start = None;
    for (index, &byte) in bytes.iter().enumerate() {
        if (0x20..=0x7e).contains(&byte) {
            start.get_or_insert(index);
        } else if let Some(begin) = start.take() {
            if index - begin >= min_length {
                result.push((begin, String::from_utf8_lossy(&bytes[begin..index]).into_owned()));
            }
        }
    }
    if let Some(begin) = start {
        if bytes.len() - begin >= min_length {
            result.push((begin, String::from_utf8_lossy(&bytes[begin..]).into_owned()));
        }
    }
    result
}

fn hexdump(bytes: &[u8], offset: usize, length: usize) {
    let end = offset.saturating_add(length).min(bytes.len());
    if offset >= end {
        println!("(no bytes in requested range)");
        return;
    }
    for (line_offset, chunk) in bytes[offset..end].chunks(16).enumerate() {
        let absolute = offset + line_offset * 16;
        print!("{absolute:08x}  ");
        for index in 0..16 {
            if let Some(byte) = chunk.get(index) {
                print!("{byte:02x} ");
            } else {
                print!("   ");
            }
            if index == 7 { print!(" "); }
        }
        print!(" |{}[0m", chunk.iter().map(|byte| if (0x20..=0x7e).contains(byte) { *byte as char } else { '.' }).collect::<String>());
        println!();
    }
}

fn run(args: &[String]) -> Result<(), String> {
    if args.is_empty() {
        usage();
        return Err("missing command".into());
    }
    match args[0].as_str() {
        "info" if args.len() == 2 => {
            let bytes = read_file(Path::new(&args[1]))?;
            println!("File: {}", args[1]);
            println!("Size: {} bytes", bytes.len());
            for line in inspect(&bytes) { println!("{line}"); }
            println!("Analysis: static and read-only; file contents were not executed.");
        }
        "strings" if (2..=3).contains(&args.len()) => {
            let min = if args.len() == 3 { args[2].parse::<usize>().map_err(|_| "min-length must be a positive integer")? } else { DEFAULT_STRING_MIN };
            if min == 0 { return Err("min-length must be greater than zero".into()); }
            let bytes = read_file(Path::new(&args[1]))?;
            for (offset, value) in printable_strings(&bytes, min) { println!("{offset:08x}  {value}"); }
        }
        "hexdump" if (2..=4).contains(&args.len()) => {
            let offset = if args.len() >= 3 { args[2].parse::<usize>().map_err(|_| "offset must be a non-negative integer")? } else { 0 };
            let length = if args.len() == 4 { args[3].parse::<usize>().map_err(|_| "length must be a non-negative integer")? } else { 256 };
            let bytes = read_file(Path::new(&args[1]))?;
            hexdump(&bytes, offset, length);
        }
        "search" if args.len() == 3 => {
            let bytes = read_file(Path::new(&args[1]))?;
            let needle = args[2].as_bytes();
            if needle.is_empty() { return Err("search text must not be empty".into()); }
            let mut found = false;
            for offset in 0..=bytes.len().saturating_sub(needle.len()) {
                if bytes.get(offset..offset + needle.len()) == Some(needle) {
                    println!("match at 0x{offset:x}");
                    found = true;
                }
            }
            if !found { println!("no matches"); }
        }
        _ => {
            usage();
            return Err("invalid command or arguments".into());
        }
    }
    Ok(())
}

fn main() {
    if let Err(error) = run(&env::args().skip(1).collect::<Vec<_>>()) {
        eprintln!("error: {error}");
        process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifies_elf_and_decodes_header_fields() {
        let mut bytes = vec![0; 64];
        bytes[..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 2;
        bytes[5] = 1;
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes());
        bytes[18..20].copy_from_slice(&0x3eu16.to_le_bytes());
        bytes[24..32].copy_from_slice(&0x401000u64.to_le_bytes());
        let report = inspect(&bytes).join("\n");
        assert!(report.contains("Format: ELF"));
        assert!(report.contains("Machine: x86-64"));
        assert!(report.contains("Entry point: 0x401000"));
    }

    #[test]
    fn identifies_valid_ascii_runs_and_offsets() {
        assert_eq!(printable_strings(b"\0hello\nworld!", 5), vec![(1, "hello".into()), (7, "world!".into())]);
    }

    #[test]
    fn malformed_short_headers_are_safe() {
        assert!(inspect(b"\x7fELF").iter().any(|line| line.contains("ELF")));
        assert!(inspect(b"MZ").iter().any(|line| line.contains("DOS header")));
    }
}

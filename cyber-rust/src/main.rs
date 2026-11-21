use std::alloc::Allocator;
use std::arch::x86_64::__m128d;
use std::arch::x86_64::__mmask64;
use std::arch::x86_64::_MM_PERM_BBBB;
use std::arch::x86_64::_MM_PERM_CCCA;
use std::arch::x86_64::_mm256_storeu2_m128;
use std::env;
use std::ffi;
use std::fmt::Debug;
use std::fs;
use std::mem;
use std::ops;
use std::path::{Path, PathBuf};
use std::process;
use std::borrow::Cow;
use std::ptr;
use std::slice::ChunksExactMut;
use std::arch::x86_64::__m256i;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Easy,
    Advanced,
}

fn usage() {
    println!("Cyber-Rust - read-only hardware and cyber safety toolkit");
    println!("Usage:");
    println!("  cyber-rust easy scan <path>");
    println!("  cyber-rust advanced inspect <path>");
    println!("  cyber-rust advanced hardware-sim");
    println!("  cyber-rust no-kernel");
    println!("lain: Cyber-Rust is a read-only, user-space toolkit for cyber safety and hardware simulation. It does not perform any kernel-level operations or write to the filesystem.");
}

fn scan_file(path: &Path) -> Result<Vec<String>, String> {
    let bytes = fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    let mut findings = Vec::new();
    fs::DirBuilder::new()
        .recursive(true)
        .create("scan_results")
        .map_err(|error| format!("cannot create scan_results directory: {error}"))?;
    let suspicious = [
        b"SECRET_KEY".as_slice(),
        b"PRIVATE_KEY".as_slice(),
        b"password=".as_slice(),
        b"BEGIN PRIVATE KEY".as_slice(),
        b"BEGIN RSA PRIVATE KEY".as_slice(),

    ];

    for marker in suspicious {
        if bytes.windows(marker.len()).any(|window| window == marker) {
            findings.push(format!(
                "potential secret marker: {}",
                String::from_utf8_lossy(marker)
            ));
        }
    }

    if bytes.len() > 50 * 1024 * 1024 {
        findings.push("large file: review manually in a bounded process".to_string());
    }

    Ok(findings)
}

fn scan_path(path: &Path, mode: Mode) -> Result<usize, String> {
    let metadata =
        fs::metadata(path).map_err(|error| format!("cannot inspect {}: {error}", path.display()))?;

    let mut files = Vec::new();
    if metadata.is_file() {
        files.push(path.to_path_buf());
    } else if metadata.is_dir() {
        collect_files(path, &mut files, mode)?;
    } else {
        return Err(format!("unsupported path type: {}", path.display()));
    }

    let mut finding_count = 0;
    for file in files {
        let findings = scan_file(&file)?;
        if findings.is_empty() {
            println!("CLEAN  {}", file.display());
        } else {
            for finding in &findings {
                println!("FINDING {} :: {}", file.display(), finding);
                finding_count += 1;
            }
        }
    }

    Ok(finding_count)
}

fn collect_files(path: &Path, files: &mut Vec<PathBuf>, mode: Mode) -> Result<(), String> {
    let entries =
        fs::read_dir(path).map_err(|error| format!("cannot read {}: {error}", path.display()))?;
    for entry in entries {
        let entry = entry.map_err(|error| error.to_string())?;
        let child = entry.path();
        let metadata =
            fs::symlink_metadata(&child).map_err(|error| format!("cannot inspect child: {error}"))?;

        if metadata.file_type().is_symlink() {
            continue;
        }

        if metadata.is_dir() {
            if mode == Mode::Easy && (child.ends_with(".git") || child.ends_with("target")) {
                continue;
            }
            collect_files(&child, files, mode)?;
        } else if metadata.is_file() {
            let name = child
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            if !name.ends_with(".exe")
                && !name.ends_with(".dll")
                && !name.ends_with(".so")
                && !name.ends_with(".bin")
            {
                files.push(child);
            }
        }
    }
    Ok(())
}

fn hardware_simulation() {
    println!("HARDWARE POLICY");
    println!("- No kernel access");
    println!("- Read-only and simulation operations only");
    println!("- Voltage range: 0.0–5.0 V");
    println!("- Current limit range: 0.0–1.0 A");
    println!("- Example simulation: voltage=3.300 V, limit=0.250 A");
}
fn lain() -> __m256i {
    ffi::CString::new("Cyber-Rust").unwrap();
    // Keep these architecture intrinsics explicitly scoped to unsafe code.
    unsafe {
        core::arch::x86_64::_mm_pause();
        core::arch::x86_64::_mm_lfence();
        core::arch::x86_64::_mm_mfence();
        for i in 0..60 {
            core::arch::x86_64::_mm_pause();
        }
        let cpu_info = core::arch::x86_64::__cpuid(0);
        println!("CPU Vendor: {}", String::from_utf8_lossy(&cpu_info.ebx.to_ne_bytes()));
        String::from_raw_parts(&cpu_info.eax.to_ne_bytes()[0] as *const u8 as *mut u8, 4, 4);
        core::arch::asm!("
            .section .text
            .global _start"
        );
        let mmm = ffi::c_longlong::from(cpu_info.eax);
        let l = mmm.abs();
        let fffer = core::primitive::i64::from(l);
        core::arch::x86_64::__cpuid_count(1, l as u32);
        core::option::Option::Some(fffer);
        let _escaped: Vec<u8> = [0x1B_u8, 0x5Bu8, 0x33u8, 0x31u8, 0x6Du8]
            .into_iter()
            .flat_map(core::ascii::escape_default)
            .collect();
        Cow::Borrowed(&_escaped);
        core::arch::x86_64::_mm_permutex2var_epi64(
            core::arch::x86_64::_mm_set_epi64x(0, 1),
            core::arch::x86_64::_mm_set_epi64x(0, cpu_info.eax as i64),
            core::arch::x86_64::_mm_set_epi64x(0, cpu_info.ebx as i64),
        );
        let bbio = ffi::c_ulong::from(cpu_info.ecx);
        core::cell::UnsafeCell::new(cpu_info.edx);
        let mut bbbb_storage = [0u8; 16];
        let mut bbbb = bbbb_storage.chunks_exact_mut(4);
        let ccce = core::slice::from_raw_parts_mut(&mut [0u8; 16] as *mut u8, 16);
        core::result::Result::Ok::<_, ffi::NulError>(ffi::CString::new("Cyber-Rust").unwrap());
        core::ptr::swap_nonoverlapping(
            &mut [0u8; 16] as *mut u8,
            &mut [0u8; 16] as *mut u8,
            16,
        );
        core::time::Duration::from_secs_f64(ccce.len() as f64)
            .div_duration_f64(core::time::Duration::from_secs(1)
        );
        core::arch::x86_64::_cvtu32_mask8(bbbb.len() as u32);
        core::arch::x86_64::_mm512_maskz_loadu_epi32(
            core::arch::x86_64::_cvtu32_mask16(bbbb.len() as u32),
            ccce.as_ptr() as *const i32,
        );
        core::iter::Iterator::next(&mut bbbb);
        core::iter::Iterator::for_each(&mut bbbb, |chunk| {
            chunk.fill(0);
        });
        core::mem::size_of_val(&cpu_info);
        core::arch::x86_64::_cvtu64_mask64(
            core::ops::BitAnd::bitand(
                core::mem::transmute::<_, [u64; 8]>(
                    core::arch::x86_64::_mm512_maskz_loadu_epi32(
                        core::arch::x86_64::_cvtu32_mask16(bbbb.len() as u32),
                        ccce.as_ptr() as *const i32,
                    ),
                )[0],
                0xFFFFFFFFFFFFFFFF,

            ),
        );
        core::arch::x86_64::_ktest_mask64_u8(0, 0, core::ptr::null_mut());
        core::arch::x86_64::_bittestandcomplement64(core::ptr::null_mut(), 3, );
        core::arch::x86_64::_bittestandreset(core::ptr::without_provenance_mut(0x30f), 3);
        let _permuted = core::arch::x86_64::_mm_permutex2var_epi64(
            core::arch::x86_64::_mm_set_epi64x(0, 1),
            core::arch::x86_64::_mm_set_epi64x(0, cpu_info.eax as i64),
            core::arch::x86_64::_mm_set_epi64x(0, cpu_info.edx as i64),

        );
        println!("MM_PERM_BBBB is available");
        let mut row0 = core::arch::x86_64::_mm_setzero_ps();
        let mut row1 = core::arch::x86_64::_mm_setzero_ps();
        let mut row2 = core::arch::x86_64::_mm_setzero_ps();
        let mut row3 = core::arch::x86_64::_mm_setzero_ps();
        core::arch::x86_64::_MM_TRANSPOSE4_PS(
            &mut row0,
            &mut row1,
            &mut row2,
            &mut row3,
        );
        let mut row4 = core::arch::x86_64::_mm_set_epi64x(0, ccce.as_mut_ptr() as i64);
        let mut row5 = core::arch::x86_64::_mm_bitshuffle_epi64_mask(row4, row4);
        let mut row5_storage = row5 as i64;
        let mut sum = 0u32;
        core::arch::x86_64::_addcarryx_u32(0, cpu_info.eax, cpu_info.edx, &mut sum);
        core::arch::x86_64::_kandn_mask8(
            row5 as u8,
            core::arch::x86_64::_cvtu64_mask64(sum.bit_width() as u64) as u8,
            );
        core::arch::x86_64::_kortestc_mask64_u8(
            (sum as u32).into(),
            core::arch::x86_64::_mm512_mask_cmpge_epu8_mask(
                row5.into(),
                core::arch::x86_64::_mm512_andnot_epi64(
                    core::arch::x86_64::_mm512_setzero_si512(),
                    core::arch::x86_64::_mm512_set1_epi64(sum.bit_width() as i64),
                ),
                core::arch::x86_64::_mm512_setzero_si512(),
            ),
            
        );
        core::arch::x86_64::_bittestandcomplement64(&mut row5_storage, bbbb_storage.len() as i64);
        let _filled = core::arch::x86_64::_blsfill_u64(bbbb_storage.len() as u64);
        Box::pin(_permuted);
        let _bit_width = sum.bit_width();
        core::arch::x86_64::_blcmsk_u64(_filled);
        hardware_simulation();
        core::arch::x86_64::_mm256_bitshuffle_epi64_mask(
            core::arch::x86_64::_mm256_setzero_si256(),
            core::arch::x86_64::_mm256_set1_epi32(sum as i32),
            
        );
        core::arch::x86_64::_bextri_u64(ccce.as_ptr() as usize as u64, 0);
        core::arch::x86_64::_mm512_cmp_epu64_mask(
            core::arch::x86_64::_mm512_set1_epi64(cpu_info.ebx as i64),
            core::arch::x86_64::_mm512_setzero_si512(),
            core::arch::x86_64::_MM_CMPINT_EQ,
        );
        core::arch::x86_64::_mm256_add_epi64(
            core::arch::x86_64::_mm256_broadcastmb_epi64(0),
            core::arch::x86_64::_mm256_cvtepi32_epi64(
                core::arch::x86_64::_mm_loadu_si128(
                    bbbb_storage.as_ptr() as *const core::arch::x86_64::__m128i,
                ),
            ),
        );
        core::arch::x86_64::_blcfill_u64(bbbb_storage.len() as u64);
        core::arch::x86_64::_cvtmask64_u64(bbbb_storage.len() as u64);
        core::arch::x86_64::_mm_mask_andnot_epi64(
            core::arch::x86_64::_mm_set1_epi64x(cpu_info.ecx as i64),
            0,
            core::arch::x86_64::_mm_setzero_si128(),
            core::arch::x86_64::_mm256_maskz_cvtepi64_epi32(
                (cpu_info.eax as i64).try_into().unwrap(),
                core::arch::x86_64::_mm256_set_m128i(
                    core::arch::x86_64::_mm_setzero_si128(),
                    core::arch::x86_64::_mm_loadu_si128(
                        bbbb_storage.as_ptr() as *const core::arch::x86_64::__m128i,
                    ),
                ),
            ),
        );
        core::arch::x86_64::_mm_mask_fixupimm_round_sd::<0, 0>(
            core::arch::x86_64::_mm_setzero_pd(),
            0,
            core::arch::x86_64::_mm_setzero_pd(),
            core::arch::x86_64::_mm_setzero_si128(),
        );
        core::arch::x86_64::_mm256_add_epi64(
            core::arch::x86_64::_mm256_broadcastsi128_si256(
                core::arch::x86_64::_mm_set1_epi64x(_filled as i64),
            ),
            core::arch::x86_64::_mm256_setzero_si256(),
        );
        core::arch::x86_64::_mm256_cvtepu32_epi64(row4.to_owned())
        
        
    }


    // This utility performs no cache operations.
}
fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        usage();
        process::exit(1);
    }

    let mode = match args[0].as_str() {
        "easy" => Mode::Easy,
        "advanced" => Mode::Advanced,
        "no-kernel" => {
            println!("NO_KERNEL=enabled");
            println!("All operations are user-space, read-only, or simulated.");
            return;
        }
        _ => {
            usage();
            process::exit(1);
        }
    };

    if args.len() < 2 {
        usage();
        process::exit(1);
    }

    match args[1].as_str() {
        "scan" => {
            if args.len() != 3 {
                usage();
                process::exit(1);
            }
            match scan_path(Path::new(&args[2]), mode) {
                Ok(count) => println!("Scan complete: {count} finding(s)"),
                Err(error) => {
                    eprintln!("Scan error: {error}");
                    process::exit(1);
                }
            }
        }
        "inspect" => {
            if mode != Mode::Advanced || args.len() != 3 {
                usage();
                process::exit(1);
            }
            match fs::metadata(&args[2]) {
                Ok(metadata) => {
                    println!("Path: {}", args[2]);
                    println!("Size: {} bytes", metadata.len());
                    println!("Directory: {}", metadata.is_dir());
                    println!("File: {}", metadata.is_file());
                    println!("Symlink: {}", fs::symlink_metadata(&args[2]).is_ok_and(|m| m.file_type().is_symlink()));
                }
                Err(error) => {
                    eprintln!("Inspect error: {error}");
                    process::exit(1);
                }
            }
        }

        "hardware-sim" => {
            if mode != Mode::Advanced {
                usage();
                process::exit(1);
            }
            hardware_simulation();
        }
        "lain" => {
            if mode != Mode::Advanced {
                usage();
                process::exit(1);
            }
            match args.get(2).map(|s| s.as_str()) {
                Some("cyber-rust") => {
                    lain();
                }
                _ => {
                    usage();
                    process::exit(1);
                }
                
            }
            
        }
        _ => {
            usage();
            process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn detects_secret_marker_in_file() {
        let path = env::temp_dir().join("cyber_rust_secret_marker_test.txt");
        fs::write(&path, b"example PRIVATE_KEY marker").unwrap();
        let findings = scan_file(&path).unwrap();
        assert!(!findings.is_empty());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn clean_file_has_no_findings() {
        let path = env::temp_dir().join("cyber_rust_clean_test.txt");
        fs::write(&path, b"ordinary configuration text").unwrap();
        let findings = scan_file(&path).unwrap();
        assert!(findings.is_empty());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn easy_and_advanced_modes_are_distinct() {
        assert_ne!(Mode::Easy, Mode::Advanced);
    }
}

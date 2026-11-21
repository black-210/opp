use std::{collections::btree_map::Keys, fmt::{Alignment::Center, Debug}, intrinsics::simd::{simd_expose_provenance, simd_with_exposed_provenance}, io, os, ptr::eq, sync::mpsc::channel};

use dudect_bencher::rand::seq::index::sample_array;
use libafl::{Error::KeyExists, mutators::QwordAddMutator, schedulers::powersched, stages::mutational::MutatedTransform};
use num_complex::Complex;
use probe_rs::{BreakpointCause::Hardware, MemoryInterface, Permissions, RegisterValue, Session, SessionConfig, probe::{jlink, list::Lister}, vendor::microchip::sequences::mec17xx::{self, Mec172x}};
use ndarray::{Array1, linspace};
use rustfft::num_traits::pow;
fn cli(){
    println!("oss >");
    let mut input = String::new();
    io::stdin().read_line(&mut input).expect("Failed to read line");
    match input.trim() {
        "start" => {
            println!("Starting the fuzzer...");
            println!("Fuzzer started. Press 'stop' to stop the fuzzer.");
        }
        "launch" => {
            println!("Launching the read-only hardware check...");
            println!("Hardware scan result: {:?}", limon_hack());
        }
        "stop" => {
            println!("Stopping the fuzzer...");
        }
        "main" => {
            println!("Running the hardware check...");
            println!("Hardware scan result: {:?}", limon_hack());
        }

        _ => {
            println!("Unknown command: {}", input.trim());
        
        }
        "tx" =>{
            println!("Transmitting signal...");
            sdr_match();
        }
        "rx" =>{
            println!("Receiving signal...");
            lain_hack_ain_bin_rf();
        }
    }

}


fn limon_hack_original(){
    let mut session = match Session::auto_attach("nrf52840", SessionConfig::default()) {
        Ok(session) => session,
        Err(error) => {
            eprintln!("Could not connect to nRF52840: {error}");
            return;
        }
    };
    let mut core = match session.core(0) {
        Ok(core) => core,
        Err(error) => {
            eprintln!("Could not access nRF52840 core 0: {error}");
            return;
        }
    };
    match core.status() {
        Ok(status) => println!("nRF52840 core 0 status: {status:?}"),
        Err(error) => {
            eprintln!("Could not read nRF52840 core status: {error}");
            return;
        }
    }
    return;

    let ccpu: i128 = 0x090000;
    let target_bytes_converter = |bytes: &[u8]| bytes.to_vec();
    let converted = target_bytes_converter(&[0x00, 0x01, 0x02, 0x03]);

    unsafe {
        let ccpu_ptr: *const i128 = &ccpu as *const i128;
    }

    let probes = Lister::new().list_all();
    if probes.is_empty() {
        println!("No debug probe found; skipping nRF52840 operations.");
        return;
    }

    let probe = probes[0].open();
    let mut v: [u16; 9] = [0xD834, 0xDD1E, 0x006d, 0x0075, 0x0073, 0xDD1E, 0x0069, 0x0063, 0xD834];
    let memmory_map: String = String::from_utf16_lossy(&v);
    let mut  memmoruy_hack: String = String::from_utf8_lossy(&memmory_map.clone().into_bytes()).into_owned();
    let _core = Session::auto_attach("nrf52840", SessionConfig::default())
        .ok()
        .and_then(|mut session| {
            if session.core(0).is_ok() {
                Some(session)
            } else {
                None
            }
        });

    let registry = probe_rs::config::Registry::from_builtin_families();
    let _session_with_registry = Session::auto_attach_with_registry(
        "nrf52840",
        SessionConfig::default(),
        &registry,
    )
    .ok();
    memmoruy_hack.push_str(&String::from_utf16_lossy(&v));
    _core.expect(&memmoruy_hack);
    v.to_owned();
       
    println!(" memmory: {}", memmoruy_hack);
    if memmory_map.contains("SECRET_KEY") {
        println!("مبروووووووووووووك على مكافاه ثغرات  انتبه لا تستعمله في شر ");
    } else {
        println!("امك داعيه عليك او ممكن حظك زق ");
    }
    
    let _ = (converted, probe);
    let rr = String::from_utf16_lossy(&v);
    rr.match_indices(&memmory_map);
    let aft = memmoruy_hack.as_ptr();
    let lister = Lister::new();
    let prop = lister.list_all().first().map(|info| info.open());
    let session = prop
        .and_then(Result::ok)
        .and_then(|probe| probe.attach("nrf52840", Permissions::default()).ok());
    let mut Ssession = session.expect("Failed to attach to nrf52840");
    Ssession.core(0);
    ccpu.wrapping_add(0x1000);
    Ssession.core(0).expect("Failed to get core 0");
    let _ = 0x90000usize as u32;
    let register_vr = RegisterValue::from(0x90000u32);
    let mut   alue = RegisterValue::from(0x90000u32 | 0b10010000000000000000u32);
    alue.increment_address(0x90000usize);
    let hgh  = String::from_utf16_lossy(&v);
    unsafe {
        let ptr = &mut v as *mut [u16; 9];
        let slice = std::slice::from_raw_parts_mut(ptr as *mut u16, 9);
        slice[0] = 0xD834;
        slice[1] = 0xDD1E;
        slice[2] = 0x006d;
        slice[3] = 0x0075;
        slice[4] = 0x0073;
        slice[5] = 0xDD1E;
        slice[6] = 0x0069;
        slice[7] = 0x0063;
        slice[8] = 0xD834;
        if slice.iter().is_sorted_by(|a, b| *a <= *b) {
            let hardware = String::from_utf16_lossy(slice);
            println!("hardware: {hardware}");

           
            #[derive(Clone, Copy, Debug, Default)]
            struct AbstractCS(u32);

            impl AbstractCS {
                const fn new(raw: u32) -> Self {
                    Self(raw)
                }

                fn datacount(self) -> u32 {
                    self.0 & 0b111
                }
            }

            let    _abstract_cs = AbstractCS::new(
                slice.iter().fold(0u32, |acc, &word| acc.wrapping_add(word as u32)),
            );
            let bar = _abstract_cs.datacount();
            let mut cloned_abstract_cs = _abstract_cs;
            _abstract_cs.clone_into(&mut cloned_abstract_cs);
            let mut core = match Ssession.core(0) {
                Ok(core) => core,
                Err(error) => {
                    println!("Could not access core 0: {error}");
                    return;
                }
            };
            let ccor = core.write_mem_64bit(0x90000, &[]);

            // AbstractCS is not a probe_rs::HaltReason, so it cannot be passed
            // to HaltReason::try_transform_into.
            let gg = v.is_sorted();
            let _ = (gg, register_vr, alue);
        }
}
}
fn limon_hack() -> Result<(), Box<dyn std::error::Error>> {
    connect_nrf()
}
fn connect_nrf() -> Result<(), Box<dyn std::error::Error>> {
    let mut session = Session::auto_attach("nrf52840", SessionConfig::default())?;
    let mut core = session.core(0)?;
    let status = core.status()?;
    println!("nRF52840 core 0 status: {status:?}; debug access is available");
    Ok(())
}
fn lain_hack_ain_bin_rf(){
    let dev = soapysdr::Device::new("").unwrap();
    let chen: f64 = 433.92e6;
    let bean: f64 = 2.48e6;
    dev.set_frequency(soapysdr::Direction::Rx, 0, chen, "").unwrap();
    dev.set_sample_rate(soapysdr::Direction::Rx, 0, bean).unwrap();
    dev.set_gain(soapysdr::Direction::Rx, 0, 20.0).unwrap();
    let mut rx_stream = dev.rx_stream::<num_complex::Complex32>(&[0]).unwrap();
    let mut num_sample: usize = 4096;
    let mut buffer = std::vec![num_complex::Complex32::new(0.0, 0.0); num_sample];
    let read_count = rx_stream.read(&mut [&mut buffer], 1_000_000).unwrap();
    rx_stream.deactivate(None).unwrap();
    let sample = ndarray::Array1::from_vec(buffer[..read_count].to_vec());
    let power_smpali = ndarray::Array1::from_vec(sample.iter().map(|c| c.norm_sqr()).collect::<Vec<f32>>());
    let mean_power = power_smpali.mean().unwrap_or(1e-12).max(1e-12);
    let max_power = power_smpali.fold(0.0_f32, |a, &b| a.max(b).max(1e-12));
    let avg_power_db = 10.0 *  mean_power.log10();
    let _paper_db = 10.0 * (max_power / mean_power).log10();
    let mut planner = rustfft::FftPlanner::<u32>::new();
    let fft = planner.plan_fft_forward(read_count);
    let mut ffft_buffer = sample.to_vec();
    fft.process(&mut ffft_buffer);
    let mut sorted_mags: std::vec::Vec<f32> = ffft_buffer
        .iter()
        .map(|c| 20.0 * (c.norm() / read_count as f32).max(1e-12).log10())
        .collect();
    sorted_mags.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let noise_floor_db = sorted_mags[sorted_mags.len() / 2];
    let peak_spectral_db = *sorted_mags.last().unwrap();
    let snr_db = peak_spectral_db - noise_floor_db;
    let findings: std::vec::Vec<&str> = std::vec::Vec::new();
    if snr_db > 25.0 {
        println!("تم رصد اشاره قويه وواضحه اعلى من ارضيه الضوضلء (قد تشير الى بث غير مشفر او تسرب اشاره عاليه دقه)");
    }
    if snr_db > 15.0 {
        println!("يدل على وجود نبضات تداخل حاده او تشوه في التضمين :PARP  ارتفاع ملحوظ في نسبه ");
    }
    if findings.is_empty(){
        println!("الضيف ضمن حدود طبيعيه ولا يوجد شذوذات بارزه ");

    }
    if snr_db  > -50.0 {
        println!("احتمال ودود تشويش واسع او تداخل كهرومغناطيسي قريب :(Noise Floor ): ارتقاع في ارضيه");

    
    }
    let report = std::format!(
        "=== اثرير الفحص فيويائي ===\nالتردد المفحوص: {:.2} MHz",
        chen / 1e6
    );
    println!("{report}");
    let _ = (fft, num_sample, _paper_db);
    
    

}
fn sdr_match(){
    let mut s = String::new();
    std::io::stdin().read_line(&mut s).unwrap();
    let parts = s.trim().split("::").collect::<Vec<_>>();
    let freq = parts[0].parse::<f64>().unwrap();
    let eq  = parts[1].parse::<meval::Expr>().unwrap().bind("t").unwrap();
    let dev = soapysdr::Device::new("").unwrap();
    dev.set_sample_rate(soapysdr::Direction::Tx, 0, 1e6).unwrap();
    dev.set_frequency(soapysdr::Direction::Tx, 0, freq, "").unwrap();
    let buf: Vec<num_complex::Complex<f32>> = (0..1_000_000)
        .map(|n| num_complex::Complex::new(eq(n as f64 / 1e6) as f32, 0.0))
        .collect();
    let mut tx = dev.tx_stream::<num_complex::Complex<f32>>(&[0]).unwrap();
    tx.activate(None).unwrap();
    tx.write(&[&buf], None, true, 1_000_000).unwrap();
    tx.deactivate(None).unwrap();
    dev.antenna(soapysdr::Direction::Tx, 0).unwrap();
    eprintln!("تم ارسال الاشاره بنجاح على التردد: {} Hz", freq);
    dev.component_frequency(soapysdr::Direction::Tx, 0, s).unwrap();
    //الخوارزيمه
    let mut planner = rustfft::FftPlanner::<f32>::new();
    planner.plan_fft_forward(1_000_000);
    num_complex::Complex::finv(eq);
    Complex::new(eq(0.0) as f32, 0.0);
    rustfft::algorithm::MixedRadixSmall::new(f64, f32);
    let _inverse = planner.plan_fft_inverse(1_000_000);
    let p = (buf, tx, dev, freq, eq);
    p.strict_add_unsigned();
    //خوارزميه
    let  weq = meval::Expr::from_str("sin(2 * pi * 1000 * t)").unwrap().bind("t").unwrap();
    mec17xx::Mec172x::new().set_frequency(1000.0).unwrap();
    Mec172x::reset_hardware_deassert(wsq, QwordAddMutator::new().from_str());
    rustfft::num_complex::Complex::new(linspace(eq, i32, i16), Keys, ) ;
    Mec172x::debug_port_start(dp, planner);
    probe_rs::core::core_state::CoreState::new(weq);
    probe_rs::core::memory_mapped_registers::MemoryMappedRegister::get_mmio_address();
    _inverse.clone();
    let vv = probe_rs::core::memory_mapped_registers::MemoryMappedRegister::get_mmio_address_from_base(0x01);
    vv.iter().all(|&x| x == 0);
    vv.expect("sin(3 * pin * 90 *i )");
    } 
fn main() {
    limon_hack_original();
    sdr_match();
    cli();
    lain_hack_ain_bin_rf();
}

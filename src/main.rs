use std::io;

use libafl::{HasObjective, StdFuzzer};
use probe_rs::{MemoryInterface, Permissions, RegisterValue, Session, SessionConfig, probe::list::Lister};
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
            println!("Launching the fuzzer...");
            println!("Fuzzer launch is not available through StdFuzzer; run the configured fuzzer from main_paylode().");
            main_paylode();
            println!("fuzzing result: {:?}", limon_hack());
        }
        "stop" => {
            println!("Stopping the fuzzer...");
        }
        "main" => {
            println!("Executing main function...");
            main_paylode();
        }

        _ => {
            println!("Unknown command: {}", input.trim());
        }
    }

}

fn main_paylode() {
    let a: u32 = 0x09000;
    let mut b: u32 = 0x0900;
    let mut fuzzer = StdFuzzer::new(a, b, <() as Default>::default());
    fuzzer.set_share_objectives(true);

    let oop = a.wrapping_add(b);

    let h = fuzzer.objective();
    let op = fuzzer.objective_mut();
}
fn limon_hack(){
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
        }

    let gg = v.is_sorted();

    let _ = (register_vr, alue);
    
}
}
fn main() {
    cli();
    main_paylode();
    limon_hack();
}

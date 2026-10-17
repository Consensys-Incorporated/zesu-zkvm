use std::{env, fs, path::PathBuf, process, time::Instant};

use eyre::{bail, Result, WrapErr};
use pico_vm::{
    compiler::riscv::program::Program,
    configs::{config::StarkGenericConfig, stark_config::KoalaBearPoseidon2},
    emulator::{opts::EmulatorOpts, stdin::EmulatorStdinBuilder},
    machine::logger::setup_logger,
    proverchain::{InitialProverSetup, MachineProver, RiscvProver},
};

type SC = KoalaBearPoseidon2;

const USAGE: &str = "Usage: {} -e <elf_path> -i <input_file> [-p] [-o <output_file>]

  -e  guest ELF
  -i  input file, fed to the guest as a single stdin entry
  -p  also generate and verify a RISCV-phase proof (default: execute only)
  -o  write the guest's public values (the bytes it wrote to fd 3) here";

fn main() -> Result<()> {
    // Guest stdout/stderr (zkvm_log) reaches the host via the `log` facade; set RUST_LOG=info to see it.
    setup_logger();
    let args: Vec<String> = env::args().collect();

    let mut elf_path: Option<PathBuf> = None;
    let mut input_path: Option<PathBuf> = None;
    let mut output_path: Option<PathBuf> = None;
    let mut prove = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-p" => prove = true,
            "-e" if i + 1 < args.len() => { elf_path = Some(PathBuf::from(&args[i + 1])); i += 1; }
            "-i" if i + 1 < args.len() => { input_path = Some(PathBuf::from(&args[i + 1])); i += 1; }
            "-o" if i + 1 < args.len() => { output_path = Some(PathBuf::from(&args[i + 1])); i += 1; }
            other => { eprintln!("unknown argument: {}", other); process::exit(1); }
        }
        i += 1;
    }
    let (Some(elf_path), Some(input_path)) = (elf_path, input_path) else {
        eprintln!("{}", USAGE.replace("{}", &args[0]));
        process::exit(1);
    };

    let elf = fs::read(&elf_path).wrap_err_with(|| format!("reading {}", elf_path.display()))?;
    let input = fs::read(&input_path).wrap_err_with(|| format!("reading {}", input_path.display()))?;

    let prover = RiscvProver::<SC, Program>::new_initial_prover(
        (SC::new(), &elf),
        EmulatorOpts::default(),
        None,
    );

    // The whole input file is one stdin entry; the guest reads it with HINT_LEN + HINT_READ.
    let stdin = || {
        let mut b = EmulatorStdinBuilder::<Vec<u8>, SC>::default();
        b.write_slice(&input);
        b.finalize().0
    };

    let start = Instant::now();
    let public_values = if prove {
        let proof = prover.prove(stdin());
        eprintln!("prove: {:.2?}", start.elapsed());
        if !prover.verify(&proof, prover.vk()) {
            bail!("RISCV proof did not verify");
        }
        eprintln!("verify: ok");
        proof.pv_stream.clone().unwrap_or_default()
    } else {
        let (reports, pv) = prover.emulate(stdin());
        let cycles = reports.last().map(|r| r.current_cycle).unwrap_or(0);
        eprintln!("execute: {:.2?}, {} cycles", start.elapsed(), cycles);
        pv
    };

    if let Some(path) = output_path {
        fs::write(&path, &public_values).wrap_err_with(|| format!("writing {}", path.display()))?;
    }
    println!("public values: {} bytes", public_values.len());
    Ok(())
}

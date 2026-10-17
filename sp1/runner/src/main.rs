use std::{env, fs, path::PathBuf, process, sync::Arc};

use eyre::{Result, WrapErr};
use sp1_sdk::{Elf, Prover, ProverClient, SP1Stdin};

const USAGE: &str = "Usage: {} -e <elf_path> -i <input_file> [-o <output_file>]

  -e  guest ELF
  -i  input file (8-byte length header + SSZ payload); the payload is fed to the guest as a
      single stdin entry
  -o  write the guest's public output (the bytes it passed to write_output) here";

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    let mut elf_path: Option<PathBuf> = None;
    let mut input_path: Option<PathBuf> = None;
    let mut output_path: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
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

    // The test vectors use ZisK's input format: an 8-byte little-endian payload length, the SSZ
    // payload, then padding to a multiple of 8. The zkvm-standards io-interface hands the guest
    // just the payload, so strip the header and padding here.
    eyre::ensure!(input.len() >= 8, "input shorter than the 8-byte length header");
    let payload_len = u64::from_le_bytes(input[..8].try_into().unwrap()) as usize;
    eyre::ensure!(
        payload_len <= input.len() - 8,
        "header payload length {} exceeds the {} bytes that follow it",
        payload_len,
        input.len() - 8
    );
    let payload = &input[8..8 + payload_len];

    // The guest reads its input with read_input(), which exposes only the FIRST stdin chunk:
    // the whole payload must be one write_slice call.
    let mut stdin = SP1Stdin::new();
    stdin.write_slice(payload);

    // Execution only: the "light" client has no proving backend.
    let client = ProverClient::builder().light().build().await;
    let (public_values, report) = client
        .execute(Elf::Dynamic(Arc::from(elf)), stdin)
        .await
        .map_err(|e| eyre::eyre!("execution failed: {e}"))?;

    let instructions = report.total_instruction_count();
    let syscalls = report.total_syscall_count();
    eprintln!("execute: {} instructions, {} syscalls", instructions, syscalls);

    let out = public_values.as_slice();
    if let Some(path) = output_path {
        fs::write(&path, out).wrap_err_with(|| format!("writing {}", path.display()))?;
    }
    println!("public values: {} bytes", out.len());
    Ok(())
}

use std::{env, fs, path::PathBuf, process, time::Instant};

use eyre::{bail, Result, WrapErr};
use pico_prover::{Prover, Stdin};
use pico_vm::machine::logger::setup_logger;

const USAGE: &str = "Usage: {} -e <elf_path> -i <input_file> [-X] [-p] [-o <output_file>]

  -e  guest ELF
  -i  input file (8-byte length header + SSZ payload); the payload is fed to the guest as a
      single stdin entry
  -X  execute as proving does (chunked) and print stats: cycles, throughput, chunks,
      misaligned accesses and per-precompile call counts
  -p  prove the full recursion chain in whitelist mode, as ere's ere-server-pico does; the prover
      verifies the proof itself before returning (default: execute only)
  -o  write the guest's public values (the bytes it wrote to fd 3) here";

fn main() -> Result<()> {
    // Guest stdout/stderr (zkvm_log) reaches the host via the `log` facade; set RUST_LOG=info to see it.
    setup_logger();
    let args: Vec<String> = env::args().collect();

    let mut elf_path: Option<PathBuf> = None;
    let mut input_path: Option<PathBuf> = None;
    let mut output_path: Option<PathBuf> = None;
    let mut prove = false;
    let mut stats = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-p" => prove = true,
            "-X" => stats = true,
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
    // payload, then padding to a multiple of 8. ere hands the guest just the payload, so strip the
    // header and padding here. The payload is one stdin entry; the guest reads it with
    // HINT_LEN + HINT_READ.
    eyre::ensure!(input.len() >= 8, "input shorter than the 8-byte length header");
    let payload_len = u64::from_le_bytes(input[..8].try_into().unwrap()) as usize;
    eyre::ensure!(
        payload_len <= input.len() - 8,
        "header payload length {} exceeds the {} bytes that follow it",
        payload_len,
        input.len() - 8
    );
    let payload = &input[8..8 + payload_len];
    let stdin = || {
        let mut s = Stdin::new();
        s.write_bytes(payload);
        s
    };
    // Same builder ere's PicoProver uses (crates/prover/pico in eth-act/ere): whitelist mode under
    // the whitelist compiled into pico-prover.
    let builder = Prover::builder(&elf).shipped_whitelist();

    let public_values = if prove {
        let mut prover = builder.build().map_err(|e| eyre::eyre!("prover setup failed: {e}"))?;
        let start = Instant::now();
        let proof = prover.prove(stdin()).map_err(|e| eyre::eyre!("prove failed: {e}"))?;
        eprintln!("prove + verify: {:.2?}", start.elapsed());
        if !proof.binds_complete_execution() {
            bail!("proof does not bind the complete execution");
        }
        proof.committed().as_bytes().to_vec()
    } else if stats {
        // Chunked emulation, exactly as the built prover would emulate; no keygen.
        let start = Instant::now();
        let ex = builder.execute_chunked(stdin()).map_err(|e| eyre::eyre!("emulation failed: {e}"))?;
        let secs = start.elapsed().as_secs_f64();
        eprintln!("execute (chunked): {:.2}s, {} cycles", secs, ex.cycles);

        let mut calls: Vec<_> = ex.precompile_calls.iter().collect();
        calls.sort_by(|a, b| b.1.cmp(a.1).then_with(|| format!("{:?}", a.0).cmp(&format!("{:?}", b.0))));
        let total: u64 = calls.iter().map(|(_, n)| **n).sum();
        section("REPORT");
        kv("CYCLES", group(ex.cycles));
        kv("THROUGHPUT", format!("{:.1} M/s", ex.cycles as f64 / secs / 1e6));
        kv("CHUNKS", group(ex.chunks as u64));
        kv("MISALIGNED ACCESSES", group(ex.misaligned_accesses));
        kv("PRECOMPILE CALLS", group(total));
        table("PRECOMPILE", "COUNT");
        for (code, n) in calls {
            row(&format!("{:?}", code), *n, 100.0 * *n as f64 / total.max(1) as f64);
        }
        println!();
        ex.committed_bytes
    } else {
        // Pure execution: no chunks, records or keygen. Runs on Pico's interpreter here (ere's
        // server builds a pure-mode AOT library first); both give the same committed bytes.
        let start = Instant::now();
        let ex = builder.execute(stdin()).map_err(|e| eyre::eyre!("execution failed: {e}"))?;
        eprintln!("execute: {:.2?}, {} cycles ({:?})", start.elapsed(), ex.cycles, ex.engine);
        ex.committed_bytes
    };

    if let Some(path) = output_path {
        fs::write(&path, &public_values).wrap_err_with(|| format!("writing {}", path.display()))?;
    }
    println!("public values: {} bytes", public_values.len());
    Ok(())
}

// Report layout: a label column, a count column and a percent column, under a rule of the same
// total width.
const LABEL_W: usize = 56;
const NUM_W: usize = 16;
const PCT_W: usize = 9;
const RULE_W: usize = LABEL_W + 1 + NUM_W + 1 + PCT_W;

fn section(title: &str) {
    println!("\n{}\n{}", title, "=".repeat(RULE_W));
}

fn kv(label: &str, value: String) {
    println!("{:<LABEL_W$} {:>NUM_W$}", label, value);
}

fn table(label: &str, num: &str) {
    println!();
    println!("{:<LABEL_W$} {:>NUM_W$} {:>PCT_W$}", label, num, "%");
    println!("{}", "-".repeat(RULE_W));
}

fn row(label: &str, n: u64, pct: f64) {
    let label: String = label.chars().take(LABEL_W).collect();
    println!("{:<LABEL_W$} {:>NUM_W$} {:>PCT_W$}", label, group(n), format!("{:.2}%", pct));
}

fn group(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

use std::{env, fs, path::PathBuf, process, sync::Arc};

use eyre::{Result, WrapErr};
use sp1_sdk::{Elf, ExecutionReport, Prover, ProverClient, SP1Stdin};
use std::time::Instant;

const USAGE: &str = "Usage: {} -e <elf_path> -i <input_file> [-X] [-o <output_file>]

  -e  guest ELF
  -i  input file (8-byte length header + SSZ payload); the payload is fed to the guest as a
      single stdin entry
  -X  print execution stats: instructions, throughput, gas, opcode mix and per-syscall counts
  -o  write the guest's public output (the bytes it passed to write_output) here";

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    let mut elf_path: Option<PathBuf> = None;
    let mut input_path: Option<PathBuf> = None;
    let mut output_path: Option<PathBuf> = None;
    let mut stats = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-e" if i + 1 < args.len() => { elf_path = Some(PathBuf::from(&args[i + 1])); i += 1; }
            "-i" if i + 1 < args.len() => { input_path = Some(PathBuf::from(&args[i + 1])); i += 1; }
            "-X" => stats = true,
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
    let start = Instant::now();
    let (public_values, report) = client
        .execute(Elf::Dynamic(Arc::from(elf)), stdin)
        .calculate_gas(true)
        .await
        .map_err(|e| eyre::eyre!("execution failed: {e}"))?;

    let secs = start.elapsed().as_secs_f64();
    if stats {
        print_stats(&report, secs);
    } else {
        eprintln!(
            "execute: {} instructions, {} syscalls",
            report.total_instruction_count(),
            report.total_syscall_count()
        );
    }

    let out = public_values.as_slice();
    if let Some(path) = output_path {
        fs::write(&path, out).wrap_err_with(|| format!("writing {}", path.display()))?;
    }
    println!("public values: {} bytes", out.len());
    Ok(())
}

/// `-X` report: instructions, throughput and gas, then the opcode mix and how many times each
/// precompile syscall ran. SP1's gas is its own proving-cost estimate; there is no per-category
/// cost table like ziskemu's.
fn print_stats(report: &ExecutionReport, secs: f64) {
    let instructions = report.total_instruction_count();
    let syscalls = report.total_syscall_count();

    section("REPORT");
    kv("INSTRUCTIONS", group(instructions));
    kv("THROUGHPUT", format!("{:.1} M/s", instructions as f64 / secs / 1e6));
    if let Some(gas) = report.gas() {
        kv("GAS", group(gas));
    }
    kv("SYSCALLS", group(syscalls));

    let mut ops: Vec<_> = report.opcode_counts.iter().filter(|(_, n)| **n > 0).collect();
    ops.sort_by(|a, b| b.1.cmp(a.1).then_with(|| format!("{:?}", a.0).cmp(&format!("{:?}", b.0))));
    table("INSTRUCTION MIX", "COUNT", true);
    for (op, n) in ops {
        row(&format!("{:?}", op), *n, Some(100.0 * *n as f64 / instructions.max(1) as f64));
    }

    let mut calls: Vec<_> = report.syscall_counts.iter().filter(|(_, n)| **n > 0).collect();
    calls.sort_by(|a, b| b.1.cmp(a.1).then_with(|| format!("{:?}", a.0).cmp(&format!("{:?}", b.0))));
    table("SYSCALL", "COUNT", true);
    for (code, n) in calls {
        row(&format!("{:?}", code), *n, Some(100.0 * *n as f64 / syscalls.max(1) as f64));
    }
}

// All report tables share one layout (same as the Pico runner): a label column, a count column
// and an optional percent column, under a rule of the same total width.
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

fn table(label: &str, num: &str, pct: bool) {
    println!();
    if pct {
        println!("{:<LABEL_W$} {:>NUM_W$} {:>PCT_W$}", label, num, "%");
    } else {
        println!("{:<LABEL_W$} {:>NUM_W$}", label, num);
    }
    println!("{}", "-".repeat(RULE_W));
}

fn row(label: &str, n: u64, pct: Option<f64>) {
    let label: String = label.chars().take(LABEL_W).collect();
    match pct {
        Some(p) => println!("{:<LABEL_W$} {:>NUM_W$} {:>PCT_W$}", label, group(n), format!("{:.2}%", p)),
        None => println!("{:<LABEL_W$} {:>NUM_W$}", label, group(n)),
    }
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

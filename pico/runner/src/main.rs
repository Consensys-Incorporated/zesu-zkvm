use std::{collections::HashMap, env, fs, path::PathBuf, process, time::Instant};

use elf::{abi::STT_FUNC, endian::AnyEndian, ElfBytes};
use eyre::{bail, Result, WrapErr};
use pico_vm::{
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        opcode::Opcode,
        program::Program,
    },
    configs::{config::StarkGenericConfig, stark_config::KoalaBearPoseidon2},
    emulator::{opts::EmulatorOpts, riscv::riscv_emulator::RiscvEmulator, stdin::EmulatorStdinBuilder},
    machine::logger::setup_logger,
    proverchain::{InitialProverSetup, MachineProver, RiscvProver},
};

type SC = KoalaBearPoseidon2;

const USAGE: &str = "Usage: {} -e <elf_path> -i <input_file> [-X] [-T] [-p] [-o <output_file>]

  -e  guest ELF
  -i  input file, fed to the guest as a single stdin entry
  -X  print execution stats: cycles, throughput and per-syscall counts (execute-only)
  -T  trace mode (implies -X): also record Pico's prover events and append events per chip,
      the instruction mix and a per-function cycle profile. Slower and memory-hungry.
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
    let mut stats = false;
    let mut trace = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-p" => prove = true,
            "-X" => stats = true,
            "-T" => { trace = true; stats = true; }
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

    // The whole input file is one stdin entry; the guest reads it with HINT_LEN + HINT_READ.
    let stdin = || {
        let mut b = EmulatorStdinBuilder::<Vec<u8>, SC>::default();
        b.write_slice(&input);
        b.finalize().0
    };

    let public_values = if prove {
        let prover = RiscvProver::<SC, Program>::new_initial_prover(
            (SC::new(), &elf),
            EmulatorOpts::default(),
            None,
        );
        let start = Instant::now();
        let proof = prover.prove(stdin());
        eprintln!("prove: {:.2?}", start.elapsed());
        if !prover.verify(&proof, prover.vk()) {
            bail!("RISCV proof did not verify");
        }
        eprintln!("verify: ok");
        proof.pv_stream.clone().unwrap_or_default()
    } else {
        // Execute-only: drive the emulator directly in its untraced ("simple") mode. Going through
        // `RiscvProver::emulate` instead records every event for proving, which is several times
        // slower and unused here. No proving key is generated either.
        let program = Compiler::new(SourceType::RISCV, &elf)?.compile();
        let mut emulator = RiscvEmulator::new_single::<<SC as StarkGenericConfig>::Val>(
            program,
            EmulatorOpts::default(),
            None,
        );
        let start = Instant::now();
        let mut trace_stats = trace.then(|| TraceStats::new(emulator.program.instructions.len()));
        if let Some(ts) = trace_stats.as_mut() {
            // Trace mode emits one record per chunk; aggregate each as it arrives instead of
            // keeping them all (a record holds every cpu event of its chunk).
            emulator.write_stdin(&stdin());
            loop {
                let report = emulator
                    .emulate_batch(&mut |record| ts.add(&record))
                    .map_err(|e| eyre::eyre!("emulation failed: {e:?}"))?;
                if report.done {
                    break;
                }
            }
        } else {
            emulator.run_fast(Some(stdin())).map_err(|e| eyre::eyre!("emulation failed: {e:?}"))?;
        }
        let elapsed = start.elapsed();
        let cycles = emulator.state.global_clk;
        eprintln!("execute: {:.2?}, {} cycles", elapsed, cycles);
        if stats {
            print_stats(&emulator, elapsed.as_secs_f64());
        }
        if let Some(ts) = trace_stats {
            ts.print(&emulator, &elf)?;
        }
        emulator.state.public_values_stream.clone()
    };

    if let Some(path) = output_path {
        fs::write(&path, &public_values).wrap_err_with(|| format!("writing {}", path.display()))?;
    }
    println!("public values: {} bytes", public_values.len());
    Ok(())
}

/// `-X` report: total cycles and throughput, then how many times each precompile syscall ran.
/// Pico has no per-category cost model like ziskemu's, so this is counts only.
fn print_stats(emulator: &RiscvEmulator, secs: f64) {
    let cycles = emulator.state.global_clk;
    let mut counts: Vec<_> = emulator.state.syscall_counts.iter().collect();
    counts.sort_by(|a, b| b.1.cmp(a.1).then_with(|| format!("{:?}", a.0).cmp(&format!("{:?}", b.0))));
    let total: u64 = counts.iter().map(|(_, n)| **n).sum();

    section("REPORT");
    kv("CYCLES", group(cycles));
    kv("THROUGHPUT", format!("{:.1} M/s", cycles as f64 / secs / 1e6));
    kv("SYSCALLS", group(total));
    table("SYSCALL", "COUNT", true);
    for (code, n) in counts {
        row(&format!("{:?}", code), *n, Some(100.0 * *n as f64 / total.max(1) as f64));
    }
}

// All report tables share one layout: a label column, a count column and an optional percent
// column, under a rule of the same total width.
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

/// What `-T` collects from Pico's prover events, aggregated per chunk record as it is emitted.
struct TraceStats {
    chunks: u64,
    cpu_events: u64,
    /// Executed instructions by opcode.
    opcodes: HashMap<Opcode, u64>,
    /// Executions per instruction slot, indexed by (pc - pc_base) / 4.
    pc_hits: Vec<u64>,
    /// Event counts per chip-ish category.
    chips: Vec<(&'static str, u64)>,
}

// byte_lookups / poseidon2 are filled in later by the prover, so they are not listed.
const CHIPS: [&str; 13] = [
    "cpu", "add", "sub", "mul", "bitwise", "shift_left", "shift_right", "divrem", "lt",
    "memory_init", "memory_finalize", "memory_local", "syscall",
];

impl TraceStats {
    fn new(program_len: usize) -> Self {
        Self {
            chunks: 0,
            cpu_events: 0,
            opcodes: HashMap::new(),
            pc_hits: vec![0; program_len],
            chips: CHIPS.iter().map(|n| (*n, 0)).collect(),
        }
    }

    fn add(&mut self, r: &pico_vm::emulator::riscv::record::EmulationRecord) {
        self.chunks += 1;
        self.cpu_events += r.cpu_events.len() as u64;
        let base = r.program.pc_base;
        for e in &r.cpu_events {
            *self.opcodes.entry(e.instruction.opcode).or_default() += 1;
            if let Some(slot) = (e.pc.wrapping_sub(base) / 4).try_into().ok().and_then(|i: usize| self.pc_hits.get_mut(i)) {
                *slot += 1;
            }
        }
        let counts: [u64; 13] = [
            r.cpu_events.len() as u64,
            r.add_events.len() as u64,
            r.sub_events.len() as u64,
            r.mul_events.len() as u64,
            r.bitwise_events.len() as u64,
            r.shift_left_events.len() as u64,
            r.shift_right_events.len() as u64,
            r.divrem_events.len() as u64,
            r.lt_events.len() as u64,
            r.memory_initialize_events.len() as u64,
            r.memory_finalize_events.len() as u64,
            r.cpu_local_memory_access.len() as u64,
            r.syscall_events.len() as u64,
        ];
        for (c, n) in self.chips.iter_mut().zip(counts) {
            c.1 += n;
        }
    }

    fn print(&self, emulator: &RiscvEmulator, elf_bytes: &[u8]) -> Result<()> {
        section("TRACE");
        kv("CHUNKS", group(self.chunks));
        kv("CHUNK SIZE (cycles)", group(emulator.opts.chunk_size as u64));

        table("EVENTS PER CHIP", "COUNT", false);
        for (name, n) in &self.chips {
            row(name, *n, None);
        }

        let mut ops: Vec<_> = self.opcodes.iter().collect();
        ops.sort_by(|a, b| b.1.cmp(a.1).then_with(|| format!("{:?}", a.0).cmp(&format!("{:?}", b.0))));
        table("INSTRUCTION MIX", "COUNT", true);
        for (op, n) in ops {
            row(&format!("{:?}", op), *n, Some(100.0 * *n as f64 / self.cpu_events.max(1) as f64));
        }

        // Per-function profile: attribute each instruction slot to the nearest symbol at or
        // below it. Local labels (`.L*`) are skipped so they don't shadow the enclosing function.
        let file = ElfBytes::<AnyEndian>::minimal_parse(elf_bytes)?;
        let mut syms: Vec<(u64, String)> = Vec::new();
        if let Some((table, strings)) = file.symbol_table()? {
            for s in table.iter() {
                if s.st_symtype() != STT_FUNC || s.st_value == 0 {
                    continue;
                }
                if let Ok(name) = strings.get(s.st_name as usize) {
                    if !name.is_empty() && !name.starts_with(".L") {
                        syms.push((s.st_value, name.to_string()));
                    }
                }
            }
        }
        syms.sort();
        let base = emulator.program.pc_base;
        let mut by_fn: HashMap<&str, u64> = HashMap::new();
        for (i, n) in self.pc_hits.iter().enumerate().filter(|(_, n)| **n > 0) {
            let pc = base + 4 * i as u64;
            let name = match syms.partition_point(|(a, _)| *a <= pc) {
                0 => "?",
                k => syms[k - 1].1.as_str(),
            };
            *by_fn.entry(name).or_default() += *n;
        }
        let mut fns: Vec<_> = by_fn.into_iter().collect();
        fns.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        table("TOP FUNCTIONS (by cycles)", "CYCLES", true);
        for (name, n) in fns.into_iter().take(25) {
            row(name, n, Some(100.0 * n as f64 / self.cpu_events.max(1) as f64));
        }
        println!();
        Ok(())
    }
}

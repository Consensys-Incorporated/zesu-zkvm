use std::{env, fs, io::Write, path::PathBuf, process, sync::Arc};

use eyre::{eyre, Result, WrapErr};
use openvm_sdk::{
    openvm_circuit::{
        arch::{
            execution_mode::MeteredCostCtx, instructions::exe::VmExe, VmExecutionConfig,
            VmExecutor,
        },
        system::memory::merkle::public_values::extract_public_values,
    },
    StdIn, F,
};
use openvm_sdk_config::{SdkVmConfig, TranspilerConfig};
use openvm_transpiler::{elf::Elf, openvm_platform::memory::MEM_SIZE, FromElf};

/// Length of `SszStatelessValidationResult` under zkevm@v0.8.0: a flat
/// `root(32) ‖ valid(1) ‖ chain_id(8, LE) ‖ schema_id(2, LE)`. It was 105 under
/// v0.5.0, where the result nested a `SszChainConfig`.
///
/// The guest reveals in 8-byte chunks, so it touches `ceil(43/8)*8 = 48` bytes of
/// the public values and never writes the rest; anything sliced beyond the result
/// is padding, not output.
const SSZ_OUTPUT_LEN: usize = 43;

/// ere's NUM_PUBLIC_VALUES_BYTES (ere-verifier-openvm).
const NUM_PUBLIC_VALUES_BYTES: usize = 256;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    let mut elf_path: Option<PathBuf> = None;
    let mut input_path: Option<PathBuf> = None;
    let mut output_path: Option<PathBuf> = None;
    let mut metered = false;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-X" => { metered = true; }
            "-e" if i + 1 < args.len() => { elf_path   = Some(PathBuf::from(&args[i + 1])); i += 1; }
            "-i" if i + 1 < args.len() => { input_path = Some(PathBuf::from(&args[i + 1])); i += 1; }
            "-o" if i + 1 < args.len() => { output_path = Some(PathBuf::from(&args[i + 1])); i += 1; }
            other => { eprintln!("unknown argument: {}", other); process::exit(1); }
        }
        i += 1;
    }

    let elf_path = elf_path.unwrap_or_else(|| {
        eprintln!("Usage: {} -e <elf_path> -i <input_file> [-X] [-o <output_file>]", args[0]);
        process::exit(1);
    });
    let input_path = input_path.unwrap_or_else(|| {
        eprintln!("Usage: {} -e <elf_path> -i <input_file> [-X] [-o <output_file>]", args[0]);
        process::exit(1);
    });

    let vm_config = sdk_vm_config();

    let elf_bytes = fs::read(&elf_path)
        .wrap_err_with(|| format!("reading {}", elf_path.display()))?;
    let exe = transpile(&vm_config, &elf_bytes)?;

    let input_bytes = fs::read(&input_path)
        .wrap_err_with(|| format!("reading {}", input_path.display()))?;
    let stdin = stdin_from_input_file(&input_bytes)?;

    let (public_values, instret) = if metered {
        execute_metered(vm_config, &exe, stdin)?
    } else {
        let executor: VmExecutor<F, SdkVmConfig> = VmExecutor::new(vm_config)
            .map_err(|e| eyre!("build executor: {e}"))?;
        let state = executor
            .instance(&exe)
            .map_err(|e| eyre!("build instance: {e}"))?
            .execute(stdin)
            .map_err(|e| eyre!("execute: {e}"))?;
        (extract_public_values(NUM_PUBLIC_VALUES_BYTES, &state.memory.memory), 0u64)
    };

    // -X: emit a COST DISTRIBUTION table on stderr for bench tool metrics scraping.
    // INSTRUCTIONS is the retired instruction count — a deterministic complexity metric
    // unaffected by host CPU load or parallelism. TOTAL mirrors it for parsers that
    // only check TOTAL.
    if metered {
        eprintln!("COST DISTRIBUTION");
        eprintln!("INSTRUCTIONS {:>24} 100.00%", instret);
        eprintln!("TOTAL        {:>24} 100.00%", instret);
    }

    if public_values.len() < SSZ_OUTPUT_LEN {
        return Err(eyre!(
            "public values too short: {} bytes, expected >= {}",
            public_values.len(),
            SSZ_OUTPUT_LEN
        ));
    }
    let output = &public_values[..SSZ_OUTPUT_LEN];

    match output_path {
        Some(ref path) => {
            fs::write(path, output)
                .wrap_err_with(|| format!("writing {}", path.display()))?;
        }
        None => {
            std::io::stdout().write_all(output)?;
        }
    }

    Ok(())
}

/// The VM config eth-act/ere executes every OpenVM guest with
/// (`sdk_vm_config` in ere-prover-openvm): the SDK's standard extension set,
/// whose modulus and curve order fixes the indices the guest's accelerators
/// encode, plus 256 public-value bytes.
fn sdk_vm_config() -> SdkVmConfig {
    let mut config = SdkVmConfig::standard();
    config.system.config = config
        .system
        .config
        .with_public_values_bytes(NUM_PUBLIC_VALUES_BYTES);
    config.optimize()
}

/// Mirrors ere's `transpile`.
fn transpile(vm_config: &SdkVmConfig, elf_bytes: &[u8]) -> Result<Arc<VmExe<F>>> {
    let elf = Elf::decode(elf_bytes, MEM_SIZE.try_into().unwrap())
        .map_err(|e| eyre!("decode ELF: {e}"))?;
    let exe = VmExe::from_elf(elf, vm_config.transpiler())
        .map_err(|e| eyre!("transpile ELF: {e}"))?;
    Ok(Arc::new(exe))
}

/// Builds the hint stream ere builds: the raw `statelessInputBytes`, as one entry.
///
/// Input files keep the vector format shared with the ZisK target —
/// `payload_len (u64 LE) ‖ SSZ payload`, zero-padded to 8 bytes — so only the
/// payload is handed to the guest.
fn stdin_from_input_file(file: &[u8]) -> Result<StdIn> {
    let header: [u8; 8] = file
        .get(..8)
        .and_then(|h| h.try_into().ok())
        .ok_or_else(|| eyre!("input file shorter than its 8-byte length header"))?;
    let payload_len = usize::try_from(u64::from_le_bytes(header))?;
    let payload = file
        .get(8..8 + payload_len)
        .ok_or_else(|| eyre!("input header claims {payload_len} bytes, file has {}", file.len() - 8))?;
    let mut stdin = StdIn::default();
    stdin.write_bytes(payload);
    Ok(stdin)
}

/// Execute with instruction-count metering, without triggering AppProvingKey keygen.
///
/// Uses a MeteredCostCtx whose AIR widths are all zero — this makes cost=0 but
/// leaves instret accurate. The executor_idx_to_air_idx mapping points every
/// executor to slot 0 of the dummy widths array; since width[0]=0, no cost
/// accumulates and no out-of-bounds access occurs.
fn execute_metered(vm_config: SdkVmConfig, exe: &VmExe<F>, stdin: StdIn) -> Result<(Vec<u8>, u64)> {
    // Determine the number of executors for this config. All executor indices are
    // in [0, num_executors), so a same-length all-zero mapping is always in-bounds.
    let inventory = <SdkVmConfig as VmExecutionConfig<F>>::create_executors(&vm_config)
        .map_err(|e| eyre!("create executors: {e}"))?;
    let executor_idx_to_air_idx = vec![0usize; inventory.executors.len()];

    // Single zero-width slot: on_height_change(0, delta) → cost += 0*0 = 0.
    let ctx = MeteredCostCtx::new(vec![0usize; 1]);

    let executor: VmExecutor<F, SdkVmConfig> = VmExecutor::new(vm_config)
        .map_err(|e| eyre!("build executor: {e}"))?;
    let interpreter = executor
        .metered_cost_instance(exe, &executor_idx_to_air_idx)
        .map_err(|e| eyre!("build interpreter: {e}"))?;
    let (ctx, final_state) = interpreter
        .execute_metered_cost(stdin, ctx)
        .map_err(|e| eyre!("execute: {e}"))?;

    let public_values = extract_public_values(NUM_PUBLIC_VALUES_BYTES, &final_state.memory.memory);
    Ok((public_values, ctx.instret))
}

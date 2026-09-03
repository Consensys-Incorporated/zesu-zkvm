use std::{env, fs, io::Write, path::PathBuf, process};

use eyre::{eyre, Result, WrapErr};
use num_bigint::BigUint;
use num_traits::{FromPrimitive, Zero};
use openvm_algebra_circuit::{Fp2Extension, ModularExtension};
use openvm_ecc_circuit::{CurveConfig, WeierstrassExtension, P256_CONFIG, SECP256K1_CONFIG};
use openvm_pairing_circuit::{PairingExtension, PairingCurve};
use openvm_sdk::{
    config::{AggregationSystemParams, AppConfig},
    openvm_circuit::{
        arch::{
            execution_mode::MeteredCostCtx, VmExecutionConfig, VmExecutor,
        },
        system::memory::merkle::public_values::extract_public_values,
    },
    Sdk, StdIn, F,
};
use openvm_sdk_config::SdkVmConfig;

/// Length of `SszStatelessValidationResult` under zkevm@v0.8.0: a flat
/// `root(32) ‖ valid(1) ‖ chain_id(8, LE) ‖ schema_id(2, LE)`. It was 105 under
/// v0.5.0, where the result nested a `SszChainConfig`.
///
/// The guest reveals in 8-byte chunks, so it touches `ceil(43/8)*8 = 48` bytes of
/// the public values and never writes the rest; anything sliced beyond the result
/// is padding, not output.
const SSZ_OUTPUT_LEN: usize = 43;
const NUM_PUBLIC_VALUES: usize = 112;

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

    // BN254 base field prime p and scalar field order r.
    let bn254_p = BigUint::parse_bytes(
        b"21888242871839275222246405745257275088696311157297823662689037894645226208583",
        10,
    ).unwrap();
    let bn254_r = BigUint::parse_bytes(
        b"21888242871839275222246405745257275088548364400416034343698204186575808495617",
        10,
    ).unwrap();
    let bn254_config = CurveConfig::new(
        "Bn254G1Affine".to_string(),
        bn254_p.clone(),
        bn254_r.clone(),
        BigUint::zero(),
        BigUint::from_u8(3).unwrap(),
    );

    // BLS12-381 base field prime Fq and scalar field order Fr.
    let bls12_fq = BigUint::parse_bytes(
        b"4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787",
        10,
    ).unwrap();
    let bls12_fr = BigUint::parse_bytes(
        b"52435875175126190479447740508185965837690552500527637822603658699938581184513",
        10,
    ).unwrap();
    let bls12_g1_config = CurveConfig::new(
        "Bls12_381G1Affine".to_string(),
        bls12_fq.clone(),
        bls12_fr.clone(),
        BigUint::zero(),
        BigUint::from_u8(4).unwrap(),
    );

    // Build VM config: rv64i + rv64m + io + keccak + sha2
    //   + modular (secp256k1 p, n, bn254 p, r, p256 p, n, bls12 Fq, Fr)
    //   + fp2 (Bls12_381Fp2)
    //   + ecc (secp256k1, bn254 G1, p256, bls12 G1).
    let mut vm_config = SdkVmConfig::builder()
        .system(Default::default())
        .rv64i(Default::default())
        .rv64m(Default::default())
        .io(Default::default())
        .keccak(Default::default())
        .sha2(Default::default())
        .modular(ModularExtension::new(vec![
            SECP256K1_CONFIG.modulus.clone(),
            SECP256K1_CONFIG.scalar.clone(),
            bn254_p,
            bn254_r,
            P256_CONFIG.modulus.clone(),
            P256_CONFIG.scalar.clone(),
            bls12_fq.clone(),
            bls12_fr,
        ]))
        .fp2(Fp2Extension::new(vec![
            ("Bls12_381Fp2".to_string(), bls12_fq),
        ]))
        .ecc(WeierstrassExtension::new(vec![
            SECP256K1_CONFIG.clone(),
            bn254_config,
            P256_CONFIG.clone(),
            bls12_g1_config,
        ]))
        .pairing(PairingExtension::new(vec![PairingCurve::Bls12_381]))
        .build()
        .optimize();
    let updated_system = vm_config.as_ref().clone().with_public_values(NUM_PUBLIC_VALUES);
    *vm_config.as_mut() = updated_system;

    // Deserialize a minimal TOML to get the correct default system_params.
    // We only care about the app_vm_config here; system_params are not used in execute().
    let minimal_toml = concat!(
        "[app_vm_config.rv64i]\n",
        "[app_vm_config.rv64m]\n",
        "[app_vm_config.io]\n",
        "[app_vm_config.keccak]\n",
        "[app_vm_config.sha2]\n",
        "[app_vm_config.modular]\n",
        "supported_moduli = [\n",
        "  \"115792089237316195423570985008687907853269984665640564039457584007908834671663\",\n",
        "  \"115792089237316195423570985008687907852837564279074904382605163141518161494337\",\n",
        "  \"21888242871839275222246405745257275088696311157297823662689037894645226208583\",\n",
        "  \"21888242871839275222246405745257275088548364400416034343698204186575808495617\",\n",
        "  \"115792089210356248762697446949407573530086143415290314195533631308867097853951\",\n",
        "  \"115792089210356248762697446949407573529996955224135760342422259061068512044369\",\n",
        "  \"4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787\",\n",
        "  \"52435875175126190479447740508185965837690552500527637822603658699938581184513\",\n",
        "]\n",
        "[app_vm_config.fp2]\n",
        "supported_moduli = [\n",
        "  [\"Bls12_381Fp2\", \"4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787\"],\n",
        "]\n",
        "[[app_vm_config.ecc.supported_curves]]\n",
        "struct_name = \"Secp256k1Point\"\n",
        "modulus = \"115792089237316195423570985008687907853269984665640564039457584007908834671663\"\n",
        "scalar = \"115792089237316195423570985008687907852837564279074904382605163141518161494337\"\n",
        "a = \"0\"\n",
        "b = \"7\"\n",
        "[[app_vm_config.ecc.supported_curves]]\n",
        "struct_name = \"Bn254G1Affine\"\n",
        "modulus = \"21888242871839275222246405745257275088696311157297823662689037894645226208583\"\n",
        "scalar = \"21888242871839275222246405745257275088548364400416034343698204186575808495617\"\n",
        "a = \"0\"\n",
        "b = \"3\"\n",
        "[[app_vm_config.ecc.supported_curves]]\n",
        "struct_name = \"P256Point\"\n",
        "modulus = \"115792089210356248762697446949407573530086143415290314195533631308867097853951\"\n",
        "scalar = \"115792089210356248762697446949407573529996955224135760342422259061068512044369\"\n",
        "a = \"115792089210356248762697446949407573530086143415290314195533631308867097853948\"\n",
        "b = \"41058363725152142129326129780047268409114441015993725554835256314039467401291\"\n",
        "[[app_vm_config.ecc.supported_curves]]\n",
        "struct_name = \"Bls12_381G1Affine\"\n",
        "modulus = \"4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787\"\n",
        "scalar = \"52435875175126190479447740508185965837690552500527637822603658699938581184513\"\n",
        "a = \"0\"\n",
        "b = \"4\"\n",
        "[app_vm_config.pairing]\n",
        "supported_curves = [\"Bls12_381\"]\n",
    );
    let mut app_config: AppConfig<SdkVmConfig> = toml::from_str(minimal_toml)
        .wrap_err("building app config")?;
    app_config.app_vm_config = vm_config.clone();

    let sdk = Sdk::new(app_config, AggregationSystemParams::default())?;

    // Feed the raw input file as a single hint-stream entry.
    let input_bytes = fs::read(&input_path)
        .wrap_err_with(|| format!("reading {}", input_path.display()))?;
    let stdin = StdIn::from_bytes(&input_bytes);

    // Pass raw ELF bytes; ExecutableFormat::from(Vec<u8>) calls Elf::decode internally.
    let elf_bytes = fs::read(&elf_path)
        .wrap_err_with(|| format!("reading {}", elf_path.display()))?;

    let (public_values, instret) = if metered {
        execute_metered(&sdk, vm_config, elf_bytes, stdin)?
    } else {
        let pv = sdk.execute(elf_bytes, stdin)?;
        (pv, 0u64)
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

/// Execute with instruction-count metering, without triggering AppProvingKey keygen.
///
/// Uses VmExecutor directly (the same executor Sdk::execute() uses) with a
/// MeteredCostCtx whose AIR widths are all zero — this makes cost=0 but leaves
/// instret accurate. The executor_idx_to_air_idx mapping points every executor to
/// slot 0 of the dummy widths array; since width[0]=0, no cost accumulates and
/// no out-of-bounds access occurs.
fn execute_metered(
    sdk: &Sdk,
    vm_config: SdkVmConfig,
    elf_bytes: Vec<u8>,
    stdin: StdIn,
) -> Result<(Vec<u8>, u64)> {
    // Determine the number of executors for this config. All executor indices are
    // in [0, num_executors), so a same-length all-zero mapping is always in-bounds.
    let inventory = <SdkVmConfig as VmExecutionConfig<F>>::create_executors(&vm_config)
        .map_err(|e| eyre!("create executors: {e}"))?;
    let num_executors = inventory.executors.len();
    let executor_idx_to_air_idx = vec![0usize; num_executors];

    // Single zero-width slot: on_height_change(0, delta) → cost += 0*0 = 0.
    let ctx = MeteredCostCtx::new(vec![0usize; 1]);

    // Build executor directly — no keygen.
    let executor: VmExecutor<F, SdkVmConfig> = VmExecutor::new(vm_config)
        .map_err(|e| eyre!("build executor: {e}"))?;

    // Transpile ELF using the SDK's configured transpiler (rv64i + rv64m + io).
    let exe = sdk.convert_to_exe(elf_bytes)
        .map_err(|e| eyre!("convert ELF: {e}"))?;

    let interpreter = executor
        .metered_cost_instance(&exe, &executor_idx_to_air_idx)
        .map_err(|e| eyre!("build interpreter: {e}"))?;

    let (ctx, final_state) = interpreter
        .execute_metered_cost(stdin, ctx)
        .map_err(|e| eyre!("execute: {e}"))?;

    // MemoryImage = AddressMap; final_state.memory.memory is the MemoryImage.
    let public_values = extract_public_values(NUM_PUBLIC_VALUES, &final_state.memory.memory);

    Ok((public_values, ctx.instret))
}

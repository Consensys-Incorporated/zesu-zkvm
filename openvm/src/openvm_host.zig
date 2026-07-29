/// OpenVM host object: satisfies all extern symbol references in zesu.rv64im.o
///
/// Exports:
///   read_input / write_output          — zkvm-standards io-interface
///   zkvm_keccak256 ... zkvm_secp256r1_verify — all 19 accelerators
///   zkvm_log                           — runtime
///   ZKVM_HEAP_POS / ZKVM_HEAP_TOP — heap region vars
///   openvm_init_heap                   — called by startup.S before main()
///
/// Halt/exit is NOT handled here: main() (zesu.o) returns its status in a0;
/// startup.S branches on a0 to emit OpenVM's TERMINATE instruction directly,
/// so no exit routine or inline asm lives in this file.
///
/// Accelerator implementations delegate to stdlibs_accel.zig (accel_impl import):
///   keccak256, sha256, ecrecover, secp256k1_verify — functional (std.crypto)
///   ripemd160, modexp, bn254_*, blake2f — stubs (return failure)
///   kzg_point_eval                     — returns verified=true (mainnet only)
///   bls12_*, secp256r1_verify           — stubs (return failure)
const std = @import("std");
const accel = @import("accel_impl");
const io = @import("zkvm_io");

/// OpenVM guest memory upper bound (512 MB, matches openvm-platform MEM_SIZE).
const GUEST_MAX_MEM: usize = 0x20000000;

/// Linker-defined symbol marking the end of all ELF sections (heap start).
extern var _end: u8;

// ── Bump heap vars ────────────────────────────────────────────────────────────
// bump_alloc.zig in zesu.o reads/writes these. They are initialized by
// openvm_init_heap() (called from startup.S before main()).

export var ZKVM_HEAP_POS: usize = 0;
export var ZKVM_HEAP_TOP: usize = 0;

export fn openvm_init_heap() void {
    ZKVM_HEAP_POS = @intFromPtr(&_end);
    ZKVM_HEAP_TOP = GUEST_MAX_MEM;
}

// ── Runtime ───────────────────────────────────────────────────────────────────

export fn zkvm_log(level: u8, msg_ptr: [*]const u8, msg_len: usize) void {
    _ = level;
    io.printStr(msg_ptr[0..msg_len]);
    io.printStr("\n");
}

// ── IO — zkvm-standards io-interface ─────────────────────────────────────────

export fn read_input(buf_ptr: *[*]const u8, buf_size: *usize) void {
    io.read_input(buf_ptr, buf_size);
}

/// Adapt: zesu.o calls write_output(ptr, len) C ABI; zkvm_io takes []const u8.
export fn write_output(ptr: [*]const u8, len: usize) void {
    io.write_output(ptr[0..len]);
}

// ── Accelerators ─────────────────────────────────────────────────────────────

// Pair types — binary-compatible with extern_bridge.zig and accelerators.zig.
const Bn254PairingPair = extern struct { g1: [64]u8, g2: [128]u8 };
const Bls12G1MsmPair = extern struct { point: [96]u8, scalar: [32]u8 };
const Bls12G2MsmPair = extern struct { point: [192]u8, scalar: [32]u8 };
const Bls12PairingPair = extern struct { g1: [96]u8, g2: [192]u8 };

export fn zkvm_keccak256(data: [*]const u8, len: usize, output: *[32]u8) i32 {
    accel.keccak256(data[0..len], output);
    return 0;
}

export fn zkvm_sha256(data: [*]const u8, len: usize, output: *[32]u8) i32 {
    accel.sha256(data[0..len], output);
    return 0;
}

export fn zkvm_secp256k1_ecrecover(msg: *const [32]u8, sig: *const [64]u8, recid: u8, output: *[64]u8) i32 {
    return if (accel.ecrecover(msg, sig, recid, output)) 0 else -1;
}

export fn zkvm_secp256k1_verify(msg: *const [32]u8, sig: *const [64]u8, pubkey: *const [64]u8, verified: *bool) i32 {
    accel.secp256k1_verify(msg, sig, pubkey, verified);
    return 0;
}

export fn zkvm_ripemd160(data: [*]const u8, len: usize, output: *[32]u8) i32 {
    accel.ripemd160(data[0..len], output);
    return 0;
}

export fn zkvm_modexp(
    base: [*]const u8,
    base_len: usize,
    exp: [*]const u8,
    exp_len: usize,
    modulus: [*]const u8,
    mod_len: usize,
    output: [*]u8,
) i32 {
    _ = accel.modexp(base[0..base_len], exp[0..exp_len], modulus[0..mod_len], output[0..mod_len]);
    return 0;
}

export fn zkvm_bn254_g1_add(p1: *const [64]u8, p2: *const [64]u8, result: *[64]u8) i32 {
    return if (accel.bn254_g1_add(p1, p2, result)) 0 else -1;
}

export fn zkvm_bn254_g1_mul(point: *const [64]u8, scalar: *const [32]u8, result: *[64]u8) i32 {
    return if (accel.bn254_g1_mul(point, scalar, result)) 0 else -1;
}

export fn zkvm_bn254_pairing(pairs: [*]const Bn254PairingPair, num_pairs: usize, verified: *bool) i32 {
    return if (accel.bn254_pairing(pairs[0..num_pairs], verified)) 0 else -1;
}

export fn zkvm_blake2f(rounds: u32, h: *[64]u8, m: *const [128]u8, t: *const [16]u8, f: u8) i32 {
    return if (accel.blake2f(rounds, h, m, t, f)) 0 else -1;
}

export fn zkvm_kzg_point_eval(commitment: *const [48]u8, z: *const [32]u8, y: *const [32]u8, proof: *const [48]u8, verified: *bool) i32 {
    return if (accel.kzg_point_eval(commitment, z, y, proof, verified)) 0 else -1;
}

export fn zkvm_bls12_g1_add(p1: *const [96]u8, p2: *const [96]u8, result: *[96]u8) i32 {
    return if (accel.bls12_g1_add(p1, p2, result)) 0 else -1;
}

export fn zkvm_bls12_g1_msm(pairs: [*]const Bls12G1MsmPair, num_pairs: usize, result: *[96]u8) i32 {
    return if (accel.bls12_g1_msm(pairs[0..num_pairs], result)) 0 else -1;
}

export fn zkvm_bls12_g2_add(p1: *const [192]u8, p2: *const [192]u8, result: *[192]u8) i32 {
    return if (accel.bls12_g2_add(p1, p2, result)) 0 else -1;
}

export fn zkvm_bls12_g2_msm(pairs: [*]const Bls12G2MsmPair, num_pairs: usize, result: *[192]u8) i32 {
    return if (accel.bls12_g2_msm(pairs[0..num_pairs], result)) 0 else -1;
}

export fn zkvm_bls12_pairing(pairs: [*]const Bls12PairingPair, num_pairs: usize, verified: *bool) i32 {
    return if (accel.bls12_pairing(pairs[0..num_pairs], verified)) 0 else -1;
}

export fn zkvm_bls12_map_fp_to_g1(field_element: *const [48]u8, result: *[96]u8) i32 {
    return if (accel.bls12_map_fp_to_g1(field_element, result)) 0 else -1;
}

export fn zkvm_bls12_map_fp2_to_g2(field_element: *const [96]u8, result: *[192]u8) i32 {
    return if (accel.bls12_map_fp2_to_g2(field_element, result)) 0 else -1;
}

export fn zkvm_secp256r1_verify(msg: *const [32]u8, sig: *const [64]u8, pubkey: *const [64]u8, verified: *bool) i32 {
    accel.secp256r1_verify(msg, sig, pubkey, verified);
    return 0;
}

//! OpenVM's pairing guest library (`openvm-pairing`), exported to the Zig guest.
//!
//! The pairing check is a multi-Miller loop in software over OpenVM's Fp/Fp2
//! instructions, with the final exponentiation replaced by a hint the host
//! computes and the guest verifies. Linking OpenVM's own implementation keeps
//! the guest on the same hint protocol as the OpenVM host.
//!
//! Callers must pass points that are canonical, on the curve and in the
//! prime-order subgroup, and must drop pairs containing the identity — the
//! library does not check any of this.
#![no_std]

extern crate alloc;

use openvm_algebra_guest::{field::FieldExtension, IntMod};
use openvm_ecc_guest::AffinePoint;
use openvm_pairing::{
    bls12_381::{Bls12_381, Fp, Fp2},
    bn254::{Bn254, Fp as BnFp, Fp2 as BnFp2},
    PairingCheck,
};

// Bind the declared field and curve types to SdkVmConfig::standard()'s
// indices (the config eth-act/ere executes with; openvm/openvm.toml). The
// macros number entries by position, so every entry is listed even where this
// crate declares no type for it.
openvm_algebra_guest::moduli_macros::moduli_init! {
    "21888242871839275222246405745257275088696311157297823662689037894645226208583",
    "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    "115792089237316195423570985008687907853269984665640564039457584007908834671663",
    "115792089237316195423570985008687907852837564279074904382605163141518161494337",
    "115792089210356248762697446949407573530086143415290314195533631308867097853951",
    "115792089210356248762697446949407573529996955224135760342422259061068512044369",
    "4002409555221667393417789825735904156556882819939007885332058136124031650490837864442687629129015664037894272559787",
    "52435875175126190479447740508185965837690552500527637822603658699938581184513",
}
openvm_algebra_guest::complex_macros::complex_init! {
    "Bn254Fp2" { mod_idx = 0 },
    "Bls12_381Fp2" { mod_idx = 6 },
}
openvm_ecc_guest::sw_macros::sw_init! {
    "Bn254G1Affine",
    "Secp256k1Point",
    "P256Point",
    "Bls12_381G1Affine",
}

// Heap allocations (the Miller loop builds Vecs) go through openvm-platform's
// bump allocator, patched in vendor/openvm-platform to share the Zig guest's
// ZKVM_HEAP_POS instead of starting a second heap at `_end`.

// ── Exports ──────────────────────────────────────────────────────────────────

/// BLS12-381 multi-pairing check: returns 1 iff prod e(P_i, Q_i) == 1.
///
/// `g1` holds `n` points as x || y (48-byte little-endian each); `g2` holds `n`
/// points as x_c0 || x_c1 || y_c0 || y_c1 (48-byte little-endian each). An
/// empty product (`n == 0`) is 1.
///
/// # Safety
/// `g1` and `g2` must point to `n * 96` and `n * 192` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn zesu_openvm_bls12_381_pairing_check(
    g1: *const u8,
    g2: *const u8,
    n: usize,
) -> u8 {
    if n == 0 {
        return 1;
    }
    let g1 = core::slice::from_raw_parts(g1, n * 96);
    let g2 = core::slice::from_raw_parts(g2, n * 192);
    let p: alloc::vec::Vec<AffinePoint<Fp>> = g1
        .chunks_exact(96)
        .map(|c| AffinePoint::new(Fp::from_le_bytes_unchecked(&c[..48]), Fp::from_le_bytes_unchecked(&c[48..])))
        .collect();
    let q: alloc::vec::Vec<AffinePoint<Fp2>> = g2
        .chunks_exact(192)
        .map(|c| AffinePoint::new(Fp2::from_bytes(&c[..96]), Fp2::from_bytes(&c[96..])))
        .collect();
    Bls12_381::pairing_check(&p, &q).is_ok() as u8
}

/// BN254 multi-pairing check: returns 1 iff prod e(P_i, Q_i) == 1.
///
/// `g1` holds `n` points as x || y (32-byte little-endian each); `g2` holds `n`
/// points as x_c0 || x_c1 || y_c0 || y_c1 (32-byte little-endian each). An
/// empty product (`n == 0`) is 1.
///
/// # Safety
/// `g1` and `g2` must point to `n * 64` and `n * 128` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn zesu_openvm_bn254_pairing_check(g1: *const u8, g2: *const u8, n: usize) -> u8 {
    if n == 0 {
        return 1;
    }
    let g1 = core::slice::from_raw_parts(g1, n * 64);
    let g2 = core::slice::from_raw_parts(g2, n * 128);
    let p: alloc::vec::Vec<AffinePoint<BnFp>> = g1
        .chunks_exact(64)
        .map(|c| AffinePoint::new(BnFp::from_le_bytes_unchecked(&c[..32]), BnFp::from_le_bytes_unchecked(&c[32..])))
        .collect();
    let q: alloc::vec::Vec<AffinePoint<BnFp2>> = g2
        .chunks_exact(128)
        .map(|c| AffinePoint::new(BnFp2::from_bytes(&c[..64]), BnFp2::from_bytes(&c[64..])))
        .collect();
    Bn254::pairing_check(&p, &q).is_ok() as u8
}

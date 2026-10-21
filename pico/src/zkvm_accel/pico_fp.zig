/// Guest field backends on Pico's precompiles (the soft.zig backend contract).
///
///   Bn254Fq / Bls12381Fq / Secp256k1Fq   FP_ADD / FP_SUB / FP_MUL (+ FP2_* for bn254 and bls)
///   UintMod(modulus)                      any 256-bit prime, mul via UINT256_MUL — used for
///                                         secp256r1's field and the scalar fields (n, r)
///
/// Only referenced from guest code; the curve code in ../shared is generic over the backend so it
/// can be unit-tested natively with soft.zig.
const std = @import("std");
const sys = @import("pico_sys");
const crypto = @import("zkvm_crypto");

pub const bn254_p: [4]u64 = crypto.bn254.bn_p;
pub const bls12381_p: [6]u64 = crypto.bls12_381.P_LIMBS;
pub const secp256k1_p: [4]u64 = .{ 0xfffffffefffffc2f, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff };

pub const Bn254Fq = struct {
    pub const limbs = 4;
    pub const modulus = bn254_p;
    pub fn add(x: *[4]u64, y: *const [4]u64) void {
        sys.fpOp(sys.BN254_FP_ADD, x, y);
    }
    pub fn sub(x: *[4]u64, y: *const [4]u64) void {
        sys.fpOp(sys.BN254_FP_SUB, x, y);
    }
    pub fn mul(x: *[4]u64, y: *const [4]u64) void {
        sys.fpOp(sys.BN254_FP_MUL, x, y);
    }
    pub fn fp2_add(x: *[8]u64, y: *const [8]u64) void {
        sys.fpOp(sys.BN254_FP2_ADD, x, y);
    }
    pub fn fp2_sub(x: *[8]u64, y: *const [8]u64) void {
        sys.fpOp(sys.BN254_FP2_SUB, x, y);
    }
    pub fn fp2_mul(x: *[8]u64, y: *const [8]u64) void {
        sys.fpOp(sys.BN254_FP2_MUL, x, y);
    }
};

pub const Bls12381Fq = struct {
    pub const limbs = 6;
    pub const modulus = bls12381_p;
    pub fn add(x: *[6]u64, y: *const [6]u64) void {
        sys.fpOp(sys.BLS12381_FP_ADD, x, y);
    }
    pub fn sub(x: *[6]u64, y: *const [6]u64) void {
        sys.fpOp(sys.BLS12381_FP_SUB, x, y);
    }
    pub fn mul(x: *[6]u64, y: *const [6]u64) void {
        sys.fpOp(sys.BLS12381_FP_MUL, x, y);
    }
    pub fn fp2_add(x: *[12]u64, y: *const [12]u64) void {
        sys.fpOp(sys.BLS12381_FP2_ADD, x, y);
    }
    pub fn fp2_sub(x: *[12]u64, y: *const [12]u64) void {
        sys.fpOp(sys.BLS12381_FP2_SUB, x, y);
    }
    pub fn fp2_mul(x: *[12]u64, y: *const [12]u64) void {
        sys.fpOp(sys.BLS12381_FP2_MUL, x, y);
    }
};

pub const Secp256k1Fq = struct {
    pub const limbs = 4;
    pub const modulus = secp256k1_p;
    pub fn add(x: *[4]u64, y: *const [4]u64) void {
        sys.fpOp(sys.SECP256K1_FP_ADD, x, y);
    }
    pub fn sub(x: *[4]u64, y: *const [4]u64) void {
        sys.fpOp(sys.SECP256K1_FP_SUB, x, y);
    }
    pub fn mul(x: *[4]u64, y: *const [4]u64) void {
        sys.fpOp(sys.SECP256K1_FP_MUL, x, y);
    }
};

/// A 256-bit prime field with mul on UINT256_MUL and add/sub in software (carry chains, no
/// division). Inputs must be canonical (< modulus).
pub fn UintMod(comptime mod: [4]u64) type {
    return struct {
        pub const limbs = 4;
        pub const modulus = mod;

        pub fn add(x: *[4]u64, y: *const [4]u64) void {
            var carry: u1 = 0;
            for (0..4) |i| {
                const s1 = @addWithOverflow(x[i], y[i]);
                const s2 = @addWithOverflow(s1[0], @as(u64, carry));
                x[i] = s2[0];
                carry = s1[1] | s2[1];
            }
            if (carry == 1 or geq(x.*, mod)) subModulus(x);
        }

        pub fn sub(x: *[4]u64, y: *const [4]u64) void {
            var borrow: u1 = 0;
            for (0..4) |i| {
                const d1 = @subWithOverflow(x[i], y[i]);
                const d2 = @subWithOverflow(d1[0], @as(u64, borrow));
                x[i] = d2[0];
                borrow = d1[1] | d2[1];
            }
            if (borrow == 1) {
                var c: u1 = 0;
                for (0..4) |i| {
                    const s1 = @addWithOverflow(x[i], mod[i]);
                    const s2 = @addWithOverflow(s1[0], @as(u64, c));
                    x[i] = s2[0];
                    c = s1[1] | s2[1];
                }
            }
        }

        pub fn mul(x: *[4]u64, y: *const [4]u64) void {
            var ym: [8]u64 align(8) = undefined;
            ym[0..4].* = y.*;
            ym[4..8].* = mod;
            sys.uint256Mul(x, &ym);
        }

        fn geq(a: [4]u64, b: [4]u64) bool {
            var i: usize = 4;
            while (i > 0) {
                i -= 1;
                if (a[i] != b[i]) return a[i] > b[i];
            }
            return true;
        }

        fn subModulus(x: *[4]u64) void {
            var borrow: u1 = 0;
            for (0..4) |i| {
                const d1 = @subWithOverflow(x[i], mod[i]);
                const d2 = @subWithOverflow(d1[0], @as(u64, borrow));
                x[i] = d2[0];
                borrow = d1[1] | d2[1];
            }
        }
    };
}

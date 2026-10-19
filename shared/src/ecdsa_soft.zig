/// Software ECDSA over secp256k1 / secp256r1 using std.crypto.pcurves.
///
/// Correctness baseline for the accelerated ECDSA in secp.zig: a target with elliptic-curve
/// precompiles (e.g. Pico's SECP256K1_* / SECP256R1_*) can replace the scalar-multiplication core
/// here, and this version is what it is tested against.
const std = @import("std");

const Secp256k1 = std.crypto.ecc.Secp256k1;
const P256 = std.crypto.ecc.P256;

/// Recover the 64-byte public key (x‖y, big-endian) from a compact signature
/// r‖s over a pre-hashed message. recid 2/3 (x >= n) are not supported.
pub fn recoverSecp256k1(msg: *const [32]u8, sig: *const [64]u8, recid: u8, output: *[64]u8) bool {
    if (recid > 1) return false;
    const Scalar = Secp256k1.scalar.Scalar;
    const r = Scalar.fromBytes(sig[0..32].*, .big) catch return false;
    const s = Scalar.fromBytes(sig[32..64].*, .big) catch return false;
    if (r.isZero() or s.isZero()) return false;

    const x = Secp256k1.Fe.fromBytes(sig[0..32].*, .big) catch return false;
    const y = Secp256k1.recoverY(x, recid == 1) catch return false;
    const point_r = Secp256k1.fromAffineCoordinates(.{ .x = x, .y = y }) catch return false;

    var wide: [64]u8 = .{0} ** 64;
    @memcpy(wide[32..], msg);
    const z = Scalar.fromBytes64(wide, .big);

    const rinv = r.invert();
    const k1 = z.neg().mul(rinv);
    const k2 = s.mul(rinv);
    const q = Secp256k1.mulDoubleBasePublic(Secp256k1.basePoint, k1.toBytes(.big), point_r, k2.toBytes(.big), .big) catch return false;
    const a = q.affineCoordinates();
    output[0..32].* = a.x.toBytes(.big);
    output[32..64].* = a.y.toBytes(.big);
    return true;
}

fn verifyGeneric(comptime Curve: type, msg: *const [32]u8, sig: *const [64]u8, pubkey: *const [64]u8) bool {
    const Scalar = Curve.scalar.Scalar;
    const r = Scalar.fromBytes(sig[0..32].*, .big) catch return false;
    const s = Scalar.fromBytes(sig[32..64].*, .big) catch return false;
    if (r.isZero() or s.isZero()) return false;

    const q = Curve.fromSerializedAffineCoordinates(pubkey[0..32].*, pubkey[32..64].*, .big) catch return false;

    var wide: [64]u8 = .{0} ** 64;
    @memcpy(wide[32..], msg);
    const z = Scalar.fromBytes64(wide, .big);

    const w = s.invert();
    const k1 = z.mul(w);
    const k2 = r.mul(w);
    const p = Curve.mulDoubleBasePublic(Curve.basePoint, k1.toBytes(.big), q, k2.toBytes(.big), .big) catch return false;
    // x(P) mod n == r
    var xb: [64]u8 = .{0} ** 64;
    xb[32..].* = p.affineCoordinates().x.toBytes(.big);
    return Scalar.fromBytes64(xb, .big).equivalent(r);
}

pub fn verifySecp256k1(msg: *const [32]u8, sig: *const [64]u8, pubkey: *const [64]u8) bool {
    return verifyGeneric(Secp256k1, msg, sig, pubkey);
}

pub fn verifySecp256r1(msg: *const [32]u8, sig: *const [64]u8, pubkey: *const [64]u8) bool {
    return verifyGeneric(P256, msg, sig, pubkey);
}

/// Root of the `zkvm_crypto` module: the zkVM-independent crypto shared by the zkVM targets
/// (pico/, openvm/, ...). Importing the files through this one module (not by relative path from
/// several modules) keeps each of them in a single module, which Zig requires.
///
/// Two kinds of code live here (see shared/README.md):
///   * standalone pure-Zig primitives: ripemd160, blake2f, modexp
///   * curve code generic over a field backend (field, soft, tower, secp, bn254, bls12_381); a
///     target supplies the backend, ideally one built on its own accelerators
pub const ripemd160 = @import("ripemd160.zig");
pub const blake2f = @import("blake2f.zig");
pub const modexp = @import("modexp.zig");
pub const bls12_381_map_constants = @import("bls12_381_map_constants.zig");

pub const field = @import("field.zig");
pub const soft = @import("soft.zig");
pub const tower = @import("tower.zig");
pub const ecdsa_soft = @import("ecdsa_soft.zig");
pub const secp = @import("secp.zig");
pub const bn254 = @import("bn254.zig");
pub const bls12_381 = @import("bls12_381.zig");

#ifndef ENCRYPT_CRYPTO_KDF_HPP_
#define ENCRYPT_CRYPTO_KDF_HPP_

#include <cstddef>
#include <string>

#include "secure_mem/secure_buffer.hpp"

namespace crypto {

// Key derivation with Argon2id (RFC 9106) via libsodium crypto_pwhash_*.
//
// The pepper is NOT a native parameter of libsodium's crypto_pwhash API (unlike
// Bouncy Castle's Argon2 "secret"). Strategy chosen (documented, applied
// identically on encrypt and decrypt):
//
//   final_key = BLAKE2b(key = BLAKE2b(pepper)[:32], msg = Argon2id(password, salt))
//
// i.e. the pepper is compressed with a plain (unkeyed) BLAKE2b to a 32-byte key
// material, and that is used as the KEY of a keyed BLAKE2b whose message is the
// Argon2id output. This is a standard HMAC-style binding:
//  - Argon2id still owns password+salt entropy with its memory-hardness;
//  - the pepper adds a second independent secret that must be known to re-derive
//    the key (defense-in-depth for the memory-hard boundary);
//  - no ambiguity about concatenation lengths (password || pepper would require
//    length-prefixing to avoid "ab"+"c" == "a"+"bc");
//  - a pepper longer than BLAKE2b's 64-byte key limit is compressed first.
//
// If pepper is empty/null the Argon2id output is returned as-is.

struct kdf_profile {
  unsigned long long ops;   // Argon2id t_cost (iterations)
  std::size_t mem_kib;      // Argon2id m_cost (memory in KiB)
  std::string label;        // human-readable label shown in the UI
};

// Profile STANDARD: 64 MiB / 3 iterations (parity with the Kotlin version).
// libsodium's OPSLIMIT_MODERATE/MEMLIMIT_MODERATE (3 / 256 MiB) would be the
// library default, but we fix explicit values to keep envelopes interoperable
// with the already-released Kotlin build.
inline constexpr kdf_profile kdf_standard() {
  return kdf_profile{3, 65536, "Estándar"};
}

// Profile MAXIMUM: 256 MiB / 6 iterations (parity with the Kotlin version).
inline constexpr kdf_profile kdf_maximum() {
  return kdf_profile{6, 262144, "Máxima"};
}

// Derives a 32-byte key. `salt` must be exactly crypto_pwhash_SALTBYTES (16)
// bytes (crypto_engine generates a fresh one per encryption). The returned
// buffer is mlock'ed and wiped by its destructor (RAII). Throws
// std::invalid_argument on invalid sizes, std::bad_alloc / std::runtime_error
// on libsodium failures.
secure_mem::byte_buffer derive_key(
    const secure_mem::secure_string& password,
    const secure_mem::byte_buffer& salt,
    const secure_mem::secure_string* pepper,  // null/empty == no pepper
    const kdf_profile& profile);

}  // namespace crypto

#endif  // ENCRYPT_CRYPTO_KDF_HPP_

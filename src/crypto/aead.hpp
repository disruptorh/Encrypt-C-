#ifndef ENCRYPT_CRYPTO_AEAD_HPP_
#define ENCRYPT_CRYPTO_AEAD_HPP_

#include <cstddef>
#include <cstdint>
#include <stdexcept>

#include "secure_mem/secure_buffer.hpp"

namespace crypto {

// Authenticated encryption with XChaCha20-Poly1305 (IETF variant).
//
// Choice (fixed, non-negotiable): crypto_aead_xchacha20poly1305_ietf_* from
// libsodium. Rationale:
//  - 192-bit (24 byte) nonce: random nonce generation is safe without a
//    counter, so a full 2^96-quantum safe nonce space; no state to manage.
//  - Constant-time in pure software, no dependence on AES-NI — it runs on any
//    airgapped hardware (including CPUs without hardware AES).
//  - libsodium is already the crypto base library of the reference app.

// Thrown when tag verification fails in aead_decrypt: the data MUST NOT be
// used. No plaintext is ever released on this path.
class authentication_error : public std::runtime_error {
 public:
  explicit authentication_error(const char* m) : std::runtime_error(m) {}
};

struct aead_result {
  secure_mem::byte_buffer nonce;      // 24 bytes, random
  secure_mem::byte_buffer ciphertext; // plaintext length + 16-byte tag
};

// Encrypts `plaintext`. `key` must be crypto_aead_xchacha20poly1305_ietf_KEYBYTES
// (32) bytes. `aad` (may be null/empty) is authenticated but not encrypted.
aead_result aead_encrypt(const secure_mem::byte_buffer& key,
                         const secure_mem::byte_buffer& plaintext,
                         const std::uint8_t* aad, std::size_t aad_len);

// Decrypts and verifies. `nonce` must be NPUBBYTES (24) bytes. On tag mismatch
// throws authentication_error; on malformed sizes throws std::invalid_argument.
secure_mem::byte_buffer aead_decrypt(const secure_mem::byte_buffer& key,
                                     const secure_mem::byte_buffer& nonce,
                                     const secure_mem::byte_buffer& ciphertext,
                                     const std::uint8_t* aad, std::size_t aad_len);

}  // namespace crypto

#endif  // ENCRYPT_CRYPTO_AEAD_HPP_

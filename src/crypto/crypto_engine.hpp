#ifndef ENCRYPT_CRYPTO_CRYPTO_ENGINE_HPP_
#define ENCRYPT_CRYPTO_CRYPTO_ENGINE_HPP_

#include <cstddef>
#include <stdexcept>
#include <string>

#include "crypto/envelope.hpp"
#include "crypto/kdf.hpp"
#include "secure_mem/secure_buffer.hpp"

namespace crypto {

// Single entry point for the app's cryptography (same role as CryptoEngine in
// the Kotlin version, and the same checkSizeBudget policy). This layer is UI
// agnostic: it never includes any Dear ImGui header.
//
//   encrypt: random salt -> Argon2id(password, salt, pepper binding) -> key
//            -> XChaCha20-Poly1305(plaintext, AAD=KDF params) -> envelope
//            -> Base64 URL-safe.
//   decrypt: envelope -> AAD-verified KDF params -> same derivation -> AEAD
//            verify+decrypt.
//
// Error policy (parity with Kotlin): authentication failures produce a single
// generic message that does not distinguish "wrong password", "wrong pepper"
// or "tampered blob". Key material and the pepper are held in secure_mem
// buffers, so they are wiped by RAII on EVERY exit path, including exceptions
// (this is C++'s natural finally-equivalent; no try/finally needed).

class crypto_exception : public std::runtime_error {
 public:
  explicit crypto_exception(const char* m) : std::runtime_error(m) {}
};

// Memory budget for the current system (sysconf-based; there is no C++
// equivalent to Runtime.maxMemory()). Mirrors the Kotlin policy:
//   estimated peak = baseline + KDF memory + 10 x plaintext size
// Returns false (and thus reject) if that peak exceeds 90% of the system RAM.
// Returns true if the size cannot be measured (sysconf failure) — fail-open on
// the measurement, matching Kotlin's "maxHeap <= 0 => true".
bool check_size_budget(std::size_t kdf_mem_kib, std::size_t plaintext_bytes);

// Encrypts `plaintext` with `password` (required) and optional `pepper`
// (nullptr == no pepper; an empty pepper is treated as absent, exactly like
// kdf::derive_key). Returns the Base64 envelope blob. Throws crypto_exception
// on any failure (empty password, size budget exceeded, crypto failure). The
// `key` and pepper-derived bytes are wiped by RAII regardless of the exit path.
std::string encrypt(const secure_mem::byte_buffer& plaintext,
                    const secure_mem::secure_string& password,
                    const secure_mem::secure_string* pepper,
                    const kdf_profile& profile);

// Decrypts `blob` with `password` (required) and optional `pepper` (nullptr
// == no pepper). Returns the plaintext bytes. Throws crypto_exception on a bad
// envelope or an authentication failure (never returns partial/tampered data).
// The derived key is wiped by RAII on every path.
secure_mem::byte_buffer decrypt(
    const std::string& blob, const secure_mem::secure_string& password,
    const secure_mem::secure_string* pepper);

}  // namespace crypto

#endif  // ENCRYPT_CRYPTO_CRYPTO_ENGINE_HPP_

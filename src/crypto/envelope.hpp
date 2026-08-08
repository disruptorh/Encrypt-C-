#ifndef ENCRYPT_CRYPTO_ENVELOPE_HPP_
#define ENCRYPT_CRYPTO_ENVELOPE_HPP_

#include <cstddef>
#include <stdexcept>
#include <string>

#include "secure_mem/secure_buffer.hpp"

namespace crypto {

// Serialized envelope (encrypted blob) format:
//
//   JSON (UTF-8) -> Base64 URL-safe sin padding
//
//   {
//     "v": 1,
//     "aead": "xchacha20poly1305_ietf",
//     "kdf": "argon2id",
//     "ops": 3,
//     "mem_kib": 65536,
//     "salt": "<b64>",       // 16 bytes
//     "nonce": "<b64>",      // 24 bytes
//     "ciphertext": "<b64>"  // >= 16 bytes (Poly1305 tag included)
//   }
//
// The KDF parameters travel inside the envelope so raising the profile later
// does not break old blobs. The pepper is NEVER serialized here.
//
// AAD: when the AEAD is invoked by crypto_engine, the additional data is the
// concatenation "v|aead|kdf|ops|mem_kib" (no salt/nonce/ciphertext), produced
// by build_aad(). This authenticates the KDF parameters INSIDE the AEAD tag,
// so an attacker who edits "mem_kib"/"ops"/"v" in the JSON without re-encrypting
// cannot make the receiver derive with different parameters.
//
// This is an improvement over the original Kotlin design, where the parameter
// protection was only indirect (params were inside the ciphertext's AAD only
// implicitly through the message).

class envelope_exception : public std::runtime_error {
 public:
  explicit envelope_exception(const char* m) : std::runtime_error(m) {}
};

struct envelope {
  int version = kVersion;
  std::string aead_name;
  std::string kdf_name;
  unsigned long long ops = 0;
  std::size_t mem_kib = 0;
  secure_mem::byte_buffer salt;
  secure_mem::byte_buffer nonce;
  secure_mem::byte_buffer ciphertext;

  static constexpr int kVersion = 1;
  static constexpr const char* kAeadName = "xchacha20poly1305_ietf";
  static constexpr const char* kKdfName = "argon2id";
  static constexpr std::size_t kSaltBytes = 16;
  static constexpr std::size_t kNonceBytes = 24;
  static constexpr std::size_t kMinCiphertextBytes = 16;  // Poly1305 tag
  // Range limits (checkSizeBudget-style guard): a malicious envelope must not
  // be able to force an extreme KDF profile that exhausts memory.
  static constexpr unsigned long long kOpsMax = 16;
  static constexpr std::size_t kMemKibMin = 1;
  static constexpr std::size_t kMemKibMax = 262144;  // 256 MiB

  // Detached, stable AAD encoding: "v|aead|kdf|ops|mem_kib". Must be byte-identical
  // between encrypt and decrypt for the same logical parameters.
  static std::string build_aad(int version, const std::string& aead_name,
                               const std::string& kdf_name, unsigned long long ops,
                               std::size_t mem_kib);
};

// Serializes the envelope to Base64 URL-safe (no padding).
std::string envelope_to_base64(const envelope& e);

// Strictly parses a Base64 envelope. Throws envelope_exception on ANY failure
// (bad base64, malformed JSON, unknown/duplicate fields, unsupported version,
// unexpected algorithm names, out-of-range ops/mem_kib, wrong salt/nonce
// sizes, empty or too-short ciphertext). JSON/base64 library exceptions are
// always wrapped in envelope_exception and never leak.
envelope envelope_from_base64(const std::string& blob);

}  // namespace crypto

#endif  // ENCRYPT_CRYPTO_ENVELOPE_HPP_

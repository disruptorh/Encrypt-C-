#ifndef ENCRYPT_CRYPTO_BASE64_HPP_
#define ENCRYPT_CRYPTO_BASE64_HPP_

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>

namespace crypto {

// Base64 URL-safe WITHOUT padding (RFC 4648 §5, alphabet "URL and Filename
// safe", `=` padding omitted). This is the exact alphabet used by the Kotlin
// version of the project (java.util.Base64.getUrlEncoder().withoutPadding()),
// so envelopes stay cross-compatible.
//
// Encoding never fails. Decoding is strict:
//  - only the URL-safe alphabet is accepted (no '+', '/' or '=');
//  - a length congruent to 1 (mod 4) is rejected;
//  - non-canonical trailing bits are rejected;
//  - any other character or an oversized input throws base64_error.

class base64_error : public std::runtime_error {
 public:
  explicit base64_error(const char* m) : std::runtime_error(m) {}
};

std::string base64url_encode(const std::uint8_t* data, std::size_t len);

// Appends the base64 of `data` to `out` (avoids an extra std::string copy in
// the envelope hot path).
void base64url_encode_to(const std::uint8_t* data, std::size_t len,
                         std::string& out);

// Decodes strictly; returns the raw bytes.
std::string base64url_decode(const std::string& in);

}  // namespace crypto

#endif  // ENCRYPT_CRYPTO_BASE64_HPP_

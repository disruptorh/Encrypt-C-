#ifndef ENCRYPT_CRYPTO_JSON_HPP_
#define ENCRYPT_CRYPTO_JSON_HPP_

#include <cstddef>
#include <map>
#include <stdexcept>
#include <string>

namespace crypto::json {

// Minimal strict JSON parser, sized to the fixed envelope schema.
//
// Why hand-rolled instead of a third-party library: the envelope schema is a
// flat object of 8 known fields (no arrays, no nesting, no floats), the input
// size is bounded by the ciphertext it wraps, and the only two value types
// needed are strings and integers. This keeps the crypto/ layer free of a JSON
// dependency while remaining fully deterministic. The parse is STRICT:
//  - strings: full escape handling (\", \\, \/, \b, \f, \n, \r, \t, \uXXXX);
//  - integers: optional '-', no leading zeros (except "0"), no fractions;
//  - duplicate keys and trailing data after the object are rejected;
//  - anything else (arrays, nested objects, true/false/null, floats) is
//    rejected with parse_error.

class parse_error : public std::runtime_error {
 public:
  explicit parse_error(const char* m) : std::runtime_error(m) {}
};

struct value {
  enum class kind { string, integer };
  kind k = kind::integer;
  std::string str;
  long long integer = 0;
};

// JSON object: key -> value.
using object = std::map<std::string, value>;

// Parses a complete JSON object from [s, s+len). Throws parse_error on any
// malformed input.
object parse_object(const char* s, std::size_t len);

}  // namespace crypto::json

#endif  // ENCRYPT_CRYPTO_JSON_HPP_

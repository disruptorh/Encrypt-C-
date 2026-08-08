#include "crypto/envelope.hpp"

#include <cstdint>

#include "crypto/base64.hpp"
#include "crypto/json.hpp"

namespace crypto {

std::string envelope::build_aad(int version, const std::string& aead_name,
                                const std::string& kdf_name,
                                unsigned long long ops, std::size_t mem_kib) {
  std::string aad;
  aad.reserve(48 + aead_name.size() + kdf_name.size());
  aad.append(std::to_string(version));
  aad.push_back('|');
  aad.append(aead_name);
  aad.push_back('|');
  aad.append(kdf_name);
  aad.push_back('|');
  aad.append(std::to_string(ops));
  aad.push_back('|');
  aad.append(std::to_string(mem_kib));
  return aad;
}

std::string envelope_to_base64(const envelope& e) {
  // Manual serialization with std::string as the StringBuilder-equivalent:
  // avoids a JSON library and keeps the hot path allocation-light. The only
  // strings are URL-safe Base64 (alphabet [A-Za-z0-9_-]), which never need
  // escaping, so this is exact and fast.
  std::string json;
  json.reserve(96 + e.salt.size() * 4 / 3 + e.nonce.size() * 4 / 3 +
               e.ciphertext.size() * 4 / 3);

  json.append("{\"v\":");
  json.append(std::to_string(e.version));
  json.append(",\"aead\":\"");
  json.append(e.aead_name);
  json.append("\",\"kdf\":\"");
  json.append(e.kdf_name);
  json.append("\",\"ops\":");
  json.append(std::to_string(e.ops));
  json.append(",\"mem_kib\":");
  json.append(std::to_string(e.mem_kib));
  json.append(",\"salt\":\"");
  base64url_encode_to(e.salt.data(), e.salt.size(), json);
  json.append("\",\"nonce\":\"");
  base64url_encode_to(e.nonce.data(), e.nonce.size(), json);
  json.append("\",\"ciphertext\":\"");
  base64url_encode_to(e.ciphertext.data(), e.ciphertext.size(), json);
  json.push_back('"');
  json.push_back('}');

  return base64url_encode(reinterpret_cast<const std::uint8_t*>(json.data()),
                          json.size());
}

namespace {

std::string require_string(const json::object& obj, const std::string& key) {
  const auto it = obj.find(key);
  if (it == obj.end() || it->second.k != json::value::kind::string) {
    throw envelope_exception("sobre: campo faltante o inválido");
  }
  return it->second.str;
}

long long require_integer(const json::object& obj, const std::string& key) {
  const auto it = obj.find(key);
  if (it == obj.end() || it->second.k != json::value::kind::integer) {
    throw envelope_exception("sobre: campo faltante o inválido");
  }
  return it->second.integer;
}

secure_mem::byte_buffer require_b64(const json::object& obj,
                                    const std::string& key,
                                    std::size_t expected_bytes) {
  const std::string b64 = require_string(obj, key);
  std::string raw;
  try {
    raw = base64url_decode(b64);
  } catch (const base64_error&) {
    throw envelope_exception("sobre: campo base64 inválido");
  }
  secure_mem::byte_buffer buf;
  buf.resize(raw.size());
  std::memcpy(buf.data(), raw.data(), raw.size());
  if (expected_bytes != 0 && buf.size() != expected_bytes) {
    throw envelope_exception("sobre: tamaño de campo inesperado");
  }
  return buf;
}

}  // namespace

envelope envelope_from_base64(const std::string& blob) {
  if (blob.empty()) throw envelope_exception("sobre: blob vacío");

  std::string raw;
  try {
    raw = base64url_decode(blob);
  } catch (const base64_error&) {
    throw envelope_exception("sobre: base64 inválido");
  }

  json::object obj;
  try {
    obj = json::parse_object(raw.data(), raw.size());
  } catch (const json::parse_error&) {
    throw envelope_exception("sobre: JSON malformado");
  }

  // Strict: reject unknown fields.
  for (const auto& [key, unused] : obj) {
    (void)unused;
    if (key != "v" && key != "aead" && key != "kdf" && key != "ops" &&
        key != "mem_kib" && key != "salt" && key != "nonce" &&
        key != "ciphertext") {
      throw envelope_exception("sobre: campo desconocido");
    }
  }

  envelope e;
  e.version = static_cast<int>(require_integer(obj, "v"));
  e.aead_name = require_string(obj, "aead");
  e.kdf_name = require_string(obj, "kdf");
  const long long ops = require_integer(obj, "ops");
  const long long mem_kib = require_integer(obj, "mem_kib");

  if (e.version != envelope::kVersion) {
    throw envelope_exception("sobre: versión no soportada");
  }
  if (e.aead_name != envelope::kAeadName) {
    throw envelope_exception("sobre: algoritmo AEAD desconocido");
  }
  if (e.kdf_name != envelope::kKdfName) {
    throw envelope_exception("sobre: KDF desconocido");
  }
  if (ops < 1 || ops > static_cast<long long>(envelope::kOpsMax)) {
    throw envelope_exception("sobre: ops fuera de rango");
  }
  if (mem_kib < static_cast<long long>(envelope::kMemKibMin) ||
      mem_kib > static_cast<long long>(envelope::kMemKibMax)) {
    throw envelope_exception("sobre: mem_kib fuera de rango");
  }
  e.ops = static_cast<unsigned long long>(ops);
  e.mem_kib = static_cast<std::size_t>(mem_kib);

  // Decode binary fields only after all cheap validations pass.
  e.salt = require_b64(obj, "salt", envelope::kSaltBytes);
  e.nonce = require_b64(obj, "nonce", envelope::kNonceBytes);
  e.ciphertext = require_b64(obj, "ciphertext", 0);
  if (e.ciphertext.empty()) throw envelope_exception("sobre: ciphertext vacío");
  if (e.ciphertext.size() < envelope::kMinCiphertextBytes) {
    throw envelope_exception("sobre: ciphertext demasiado corto");
  }
  return e;
}

}  // namespace crypto

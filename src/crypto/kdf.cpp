#include "crypto/kdf.hpp"

#include <limits>
#include <new>
#include <stdexcept>

#include <sodium.h>

namespace crypto {

namespace {
constexpr std::size_t kKeyBytes = 32;
constexpr std::size_t kSaltBytes = crypto_pwhash_SALTBYTES;  // 16
}  // namespace

secure_mem::byte_buffer derive_key(const secure_mem::secure_string& password,
                                   const secure_mem::byte_buffer& salt,
                                   const secure_mem::secure_string* pepper,
                                   const kdf_profile& profile) {
  if (salt.size() != kSaltBytes) {
    throw std::invalid_argument("kdf: el salt debe tener 16 bytes");
  }
  if (profile.ops < 1) throw std::invalid_argument("kdf: ops inválido");
  if (profile.mem_kib == 0 ||
      profile.mem_kib > static_cast<std::size_t>(crypto_pwhash_MEMLIMIT_MAX / 1024)) {
    throw std::invalid_argument("kdf: mem_kib fuera de rango");
  }
  if (password.size() > static_cast<std::size_t>(crypto_pwhash_PASSWD_MAX)) {
    throw std::invalid_argument("kdf: contraseña demasiado larga");
  }

  secure_mem::byte_buffer argon_key;
  argon_key.resize(kKeyBytes);

  if (crypto_pwhash_argon2id(
          argon_key.data(), argon_key.size(), password.data(), password.size(),
          salt.data(), profile.ops, profile.mem_kib * 1024,
          crypto_pwhash_ALG_ARGON2ID13) != 0) {
    throw std::runtime_error("kdf: crypto_pwhash_argon2id falló");
  }

  if (pepper == nullptr || pepper->empty()) {
    return argon_key;
  }

  // Pepper binding: see the strategy comment in kdf.hpp.
  secure_mem::byte_buffer pepper_key;
  pepper_key.resize(crypto_generichash_BYTES);  // 32
  if (crypto_generichash(pepper_key.data(), pepper_key.size(),
                         reinterpret_cast<const unsigned char*>(pepper->data()),
                         pepper->size(), nullptr, 0) != 0) {
    throw std::runtime_error("kdf: crypto_generichash(pepper) falló");
  }

  secure_mem::byte_buffer final_key;
  final_key.resize(kKeyBytes);
  if (crypto_generichash(final_key.data(), final_key.size(), argon_key.data(),
                         argon_key.size(), pepper_key.data(),
                         pepper_key.size()) != 0) {
    throw std::runtime_error("kdf: crypto_generichash keyed falló");
  }

  return final_key;
}

}  // namespace crypto

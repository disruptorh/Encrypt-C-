#include "crypto/aead.hpp"

#include <new>

#include <sodium.h>

namespace crypto {

namespace {
constexpr std::size_t kKeyBytes = crypto_aead_xchacha20poly1305_ietf_KEYBYTES;
constexpr std::size_t kNonceBytes = crypto_aead_xchacha20poly1305_ietf_NPUBBYTES;
constexpr std::size_t kTagBytes = crypto_aead_xchacha20poly1305_ietf_ABYTES;
}  // namespace

aead_result aead_encrypt(const secure_mem::byte_buffer& key,
                         const secure_mem::byte_buffer& plaintext,
                         const std::uint8_t* aad, std::size_t aad_len) {
  if (key.size() != kKeyBytes) {
    throw std::invalid_argument("aead: la clave debe tener 32 bytes");
  }

  aead_result out;
  out.nonce.resize(kNonceBytes);
  randombytes_buf(out.nonce.data(), out.nonce.size());

  if (plaintext.size() > static_cast<std::size_t>(crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX)) {
    throw std::invalid_argument("aead: texto demasiado grande");
  }
  out.ciphertext.resize(plaintext.size() + kTagBytes);

  unsigned long long clen = 0;
  const int rc = crypto_aead_xchacha20poly1305_ietf_encrypt(
      out.ciphertext.data(), &clen, plaintext.data(), plaintext.size(), aad,
      aad_len, nullptr, out.nonce.data(), key.data());
  if (rc != 0 || clen != out.ciphertext.size()) {
    throw std::runtime_error("aead: fallo de cifrado libsodium");
  }
  return out;
}

secure_mem::byte_buffer aead_decrypt(const secure_mem::byte_buffer& key,
                                     const secure_mem::byte_buffer& nonce,
                                     const secure_mem::byte_buffer& ciphertext,
                                     const std::uint8_t* aad, std::size_t aad_len) {
  if (key.size() != kKeyBytes) {
    throw std::invalid_argument("aead: la clave debe tener 32 bytes");
  }
  if (nonce.size() != kNonceBytes) {
    throw std::invalid_argument("aead: el nonce debe tener 24 bytes");
  }
  if (ciphertext.size() < kTagBytes) {
    throw std::invalid_argument("aead: ciphertext demasiado corto");
  }

  secure_mem::byte_buffer plaintext;
  plaintext.resize(ciphertext.size() - kTagBytes);

  unsigned long long mlen = 0;
  const int rc = crypto_aead_xchacha20poly1305_ietf_decrypt(
      plaintext.data(), &mlen, nullptr, ciphertext.data(), ciphertext.size(),
      aad, aad_len, nonce.data(), key.data());
  if (rc != 0) {
    throw authentication_error("Fallo de autenticación: datos no autenticados");
  }
  if (mlen != plaintext.size()) {
    throw std::runtime_error("aead: longitud de salida inesperada");
  }
  return plaintext;
}

}  // namespace crypto
